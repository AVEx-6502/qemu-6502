/*
 *  Alpha emulation cpu translation for qemu.
 *
 *  Copyright (c) 2007 Jocelyn Mayer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "cpu.h"
#include "disas.h"
#include "host-utils.h"
#include "tcg-op.h"

#include "helper.h"
#define GEN_HELPER 1
#include "helper.h"

#undef ALPHA_DEBUG_DISAS
#define CONFIG_SOFTFLOAT_INLINE

#ifdef ALPHA_DEBUG_DISAS
#  define LOG_DISAS(...) qemu_log_mask(CPU_LOG_TB_IN_ASM, ## __VA_ARGS__)
#else
#  define LOG_DISAS(...) do { } while (0)
#endif

typedef struct DisasContext DisasContext;
struct DisasContext {
    struct TranslationBlock *tb;
    CPUAlphaState *env;
    uint64_t pc;
    int mem_idx;

    /* Current rounding mode for this TB.  */
    int tb_rm;
    /* Current flush-to-zero setting for this TB.  */
    int tb_ftz;
};

/* Return values from translate_one, indicating the state of the TB.
   Note that zero indicates that we are not exiting the TB.  */

typedef enum {
    NO_EXIT,

    /* We have emitted one or more goto_tb.  No fixup required.  */
    EXIT_GOTO_TB,

    /* We are not using a goto_tb (for whatever reason), but have updated
       the PC (for whatever reason), so there's no need to do it again on
       exiting the TB.  */
    EXIT_PC_UPDATED,

    /* We are exiting the TB, but have neither emitted a goto_tb, nor
       updated the PC for the next instruction to be executed.  */
    EXIT_PC_STALE,

    /* We are ending the TB with a noreturn function call, e.g. longjmp.
       No following code will be executed.  */
    EXIT_NORETURN,
} ExitStatus;

// The following are the register variable as taken by TCG functions
static TCGv_ptr cpu_env;
static TCGv cpu_pc;

// 6502 registers...
static TCGv_i32 regAC;
static TCGv_i32 regX;
static TCGv_i32 regY;
static TCGv_i32 regSR;
static TCGv_i32 regSP;

static TCGv cpu_ir[31];
static TCGv cpu_fir[31];
static TCGv cpu_lock_addr;
static TCGv cpu_lock_st_addr;
static TCGv cpu_lock_value;
static TCGv cpu_unique;
#ifndef CONFIG_USER_ONLY
static TCGv cpu_sysval;
static TCGv cpu_usp;
#endif

/* register names */
static char cpu_reg_names[10*4+21*5 + 10*5+21*6];

#include "gen-icount.h"

static void alpha_translate_init(void)
{
    int i;
    char *p;
    static int done_init = 0;

    if (done_init)
        return;

    cpu_env = tcg_global_reg_new_ptr(TCG_AREG0, "env");

    // Creating registers...
    regAC = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUState, ac), "AC");
    regX  = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUState,  x),  "X");
    regY  = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUState,  y),  "Y");

    regSR = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUState, sr), "SR");
    regSP = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUState, sp), "SP");


    // Old Alpha stuff kept to avoid breaking the code:
    p = cpu_reg_names;
    for (i = 0; i < 31; i++) {
        sprintf(p, "ir%d", i);
        cpu_ir[i] = tcg_global_mem_new_i64(TCG_AREG0,
                                           offsetof(CPUState, ir[i]), p);
        p += (i < 10) ? 4 : 5;

        sprintf(p, "fir%d", i);
        cpu_fir[i] = tcg_global_mem_new_i64(TCG_AREG0,
                                            offsetof(CPUState, fir[i]), p);
        p += (i < 10) ? 5 : 6;
    }

    cpu_pc = tcg_global_mem_new_i64(TCG_AREG0,
                                    offsetof(CPUState, pc), "pc");

    cpu_lock_addr = tcg_global_mem_new_i64(TCG_AREG0,
                                           offsetof(CPUState, lock_addr),
                                           "lock_addr");
    cpu_lock_st_addr = tcg_global_mem_new_i64(TCG_AREG0,
                                              offsetof(CPUState, lock_st_addr),
                                              "lock_st_addr");
    cpu_lock_value = tcg_global_mem_new_i64(TCG_AREG0,
                                            offsetof(CPUState, lock_value),
                                            "lock_value");

    cpu_unique = tcg_global_mem_new_i64(TCG_AREG0,
                                        offsetof(CPUState, unique), "unique");
#ifndef CONFIG_USER_ONLY
    cpu_sysval = tcg_global_mem_new_i64(TCG_AREG0,
                                        offsetof(CPUState, sysval), "sysval");
    cpu_usp = tcg_global_mem_new_i64(TCG_AREG0,
                                     offsetof(CPUState, usp), "usp");
#endif

    /* register helpers */
#define GEN_HELPER 2
#include "helper.h"

    done_init = 1;
}

static void gen_excp_1(int exception, int error_code)
{
    TCGv_i32 tmp1, tmp2;

    tmp1 = tcg_const_i32(exception);
    tmp2 = tcg_const_i32(error_code);
    gen_helper_excp(tmp1, tmp2);
    tcg_temp_free_i32(tmp2);
    tcg_temp_free_i32(tmp1);
}

static ExitStatus gen_excp(DisasContext *ctx, int exception, int error_code)
{
    tcg_gen_movi_i64(cpu_pc, ctx->pc);
    gen_excp_1(exception, error_code);
    return EXIT_NORETURN;
}

static inline ExitStatus gen_invalid(DisasContext *ctx)
{
    return gen_excp(ctx, EXCP_OPCDEC, 0);
}






static inline void gen_qemu_ldl_l(TCGv t0, TCGv t1, int flags)
{
    tcg_gen_qemu_ld32s(t0, t1, flags);
    tcg_gen_mov_i64(cpu_lock_addr, t1);
    tcg_gen_mov_i64(cpu_lock_value, t0);
}

static inline void gen_qemu_ldq_l(TCGv t0, TCGv t1, int flags)
{
    tcg_gen_qemu_ld64(t0, t1, flags);
    tcg_gen_mov_i64(cpu_lock_addr, t1);
    tcg_gen_mov_i64(cpu_lock_value, t0);
}

static inline void gen_load_mem(DisasContext *ctx,
                                void (*tcg_gen_qemu_load)(TCGv t0, TCGv t1,
                                                          int flags),
                                int ra, int rb, int32_t disp16, int fp,
                                int clear)
{
    TCGv addr, va;

    /* LDQ_U with ra $31 is UNOP.  Other various loads are forms of
       prefetches, which we can treat as nops.  No worries about
       missed exceptions here.  */
    if (unlikely(ra == 31)) {
        return;
    }

    addr = tcg_temp_new();
    if (rb != 31) {
        tcg_gen_addi_i64(addr, cpu_ir[rb], disp16);
        if (clear) {
            tcg_gen_andi_i64(addr, addr, ~0x7);
        }
    } else {
        if (clear) {
            disp16 &= ~0x7;
        }
        tcg_gen_movi_i64(addr, disp16);
    }

    va = (fp ? cpu_fir[ra] : cpu_ir[ra]);
    tcg_gen_qemu_load(va, addr, ctx->mem_idx);

    tcg_temp_free(addr);
}




static inline void gen_store_mem(DisasContext *ctx,
                                 void (*tcg_gen_qemu_store)(TCGv t0, TCGv t1,
                                                            int flags),
                                 int ra, int rb, int32_t disp16, int fp,
                                 int clear)
{
    TCGv addr, va;

    addr = tcg_temp_new();
    if (rb != 31) {
        tcg_gen_addi_i64(addr, cpu_ir[rb], disp16);
        if (clear) {
            tcg_gen_andi_i64(addr, addr, ~0x7);
        }
    } else {
        if (clear) {
            disp16 &= ~0x7;
        }
        tcg_gen_movi_i64(addr, disp16);
    }

    if (ra == 31) {
        va = tcg_const_i64(0);
    } else {
        va = (fp ? cpu_fir[ra] : cpu_ir[ra]);
    }
    tcg_gen_qemu_store(va, addr, ctx->mem_idx);

    tcg_temp_free(addr);
    if (ra == 31) {
        tcg_temp_free(va);
    }
}

#if 0
static int use_goto_tb(DisasContext *ctx, uint64_t dest)
{
    /* Check for the dest on the same page as the start of the TB.  We
       also want to suppress goto_tb in the case of single-steping and IO.  */
    return (((ctx->tb->pc ^ dest) & TARGET_PAGE_MASK) == 0
            && !ctx->env->singlestep_enabled
            && !(ctx->tb->cflags & CF_LAST_IO));
}
#endif

#define QUAL_RM_N       0x080   /* Round mode nearest even */
#define QUAL_RM_C       0x000   /* Round mode chopped */
#define QUAL_RM_M       0x040   /* Round mode minus infinity */
#define QUAL_RM_D       0x0c0   /* Round mode dynamic */
#define QUAL_RM_MASK    0x0c0

#define QUAL_U          0x100   /* Underflow enable (fp output) */
#define QUAL_V          0x100   /* Overflow enable (int output) */
#define QUAL_S          0x400   /* Software completion enable */
#define QUAL_I          0x200   /* Inexact detection enable */











static void gen_cpys_internal(int ra, int rb, int rc, int inv_a, uint64_t mask)
{
    TCGv va, vb, vmask;
    int za = 0, zb = 0;

    if (unlikely(rc == 31)) {
        return;
    }

    vmask = tcg_const_i64(mask);

    TCGV_UNUSED_I64(va);
    if (ra == 31) {
        if (inv_a) {
            va = vmask;
        } else {
            za = 1;
        }
    } else {
        va = tcg_temp_new_i64();
        tcg_gen_mov_i64(va, cpu_fir[ra]);
        if (inv_a) {
            tcg_gen_andc_i64(va, vmask, va);
        } else {
            tcg_gen_and_i64(va, va, vmask);
        }
    }

    TCGV_UNUSED_I64(vb);
    if (rb == 31) {
        zb = 1;
    } else {
        vb = tcg_temp_new_i64();
        tcg_gen_andc_i64(vb, cpu_fir[rb], vmask);
    }

    switch (za << 1 | zb) {
    case 0 | 0:
        tcg_gen_or_i64(cpu_fir[rc], va, vb);
        break;
    case 0 | 1:
        tcg_gen_mov_i64(cpu_fir[rc], va);
        break;
    case 2 | 0:
        tcg_gen_mov_i64(cpu_fir[rc], vb);
        break;
    case 2 | 1:
        tcg_gen_movi_i64(cpu_fir[rc], 0);
        break;
    }

    tcg_temp_free(vmask);
    if (ra != 31) {
        tcg_temp_free(va);
    }
    if (rb != 31) {
        tcg_temp_free(vb);
    }
}

static inline void gen_fcpys(int ra, int rb, int rc)
{
    gen_cpys_internal(ra, rb, rc, 0, 0x8000000000000000ULL);
}

static inline void gen_fcpysn(int ra, int rb, int rc)
{
    gen_cpys_internal(ra, rb, rc, 1, 0x8000000000000000ULL);
}

static inline void gen_fcpyse(int ra, int rb, int rc)
{
    gen_cpys_internal(ra, rb, rc, 0, 0xFFF0000000000000ULL);
}




static inline uint64_t zapnot_mask(uint8_t lit)
{
    uint64_t mask = 0;
    int i;

    for (i = 0; i < 8; ++i) {
        if ((lit >> i) & 1)
            mask |= 0xffull << (i * 8);
    }
    return mask;
}

/* Inlines for addressing modes...
 * First we have functions that load addresses.
 * Then we have functions that load values.
 */
/*
// Load address for "X,ind" addressing mode (looks like black magic but it's real!)...
// In the black lang of Mordor (6502 assembly syntax), it's written ($BB,X).
// In higher elvish (x86-like syntax), this means [[X+[ 0x?? ]]].
// The function uses the same register for all intermediate value...
static inline uint64_t gen_xind_mode_addr(TCGv_i32 reg, uint64_t code_addr)
{
    uint8_t zpg_imm = ldub_code(code_addr++);

    tcg_gen_movi_i32(reg, zpg_imm);
    tcg_gen_qemu_ld8u_i32(reg, reg);      // Inner []
    tcg_gen_addi_i32(reg, regX);            // Add X
    tcg_gen_qemu_ld16u_i32(reg, reg);     // [] around addition
    tcg_gen_qemu_ld8u_i32(reg, reg);      // Outer []

    return code_addr;
}
*/
static inline uint64_t gen_imm_mode(TCGv_i32 reg, uint64_t code_addr)
{
    uint8_t imm = ldub_code(code_addr++);
    tcg_gen_movi_i32(reg, imm);
    return code_addr;
}



static ExitStatus translate_one(DisasContext *ctx, uint64_t *paddr)
{
    fprintf(stderr, "A gerar: %"PRIX8"\n", ldub_code(*paddr));
    uint8_t insn;

    // Decode opcode . . .
    switch(insn=ldub_code((*paddr)++)) {
        case 0xA0:  // LDY imm
        {
            *paddr = gen_imm_mode(regY, *paddr);
            return NO_EXIT;
        }

        default:
        {
            TCGv_i32 tmp = tcg_temp_new_i32();
            TCGv_i64 tmp2 = tcg_temp_new_i64();
            tcg_gen_movi_i32(tmp, insn);
            tcg_gen_movi_i64(tmp2, ctx->pc);
            gen_helper_printstuff(tmp2, tmp);
            tcg_temp_free_i64(tmp2);
            tcg_temp_free_i32(tmp);
            return EXIT_PC_STALE;
        }
    }
}



static inline void gen_intermediate_code_internal(CPUState *env,
                                                  TranslationBlock *tb,
                                                  int search_pc)
{
    DisasContext ctx, *ctxp = &ctx;
    target_ulong pc_start;
    uint16_t *gen_opc_end;
    CPUBreakpoint *bp;
    int j, lj = -1;
    ExitStatus ret;
    int num_insns;
    int max_insns;

    pc_start = tb->pc;
    gen_opc_end = gen_opc_buf + OPC_MAX_SIZE;

    ctx.tb = tb;
    ctx.env = env;
    ctx.pc = pc_start;
    ctx.mem_idx = cpu_mmu_index(env);

    /* ??? Every TB begins with unset rounding mode, to be initialized on
       the first fp insn of the TB.  Alternately we could define a proper
       default for every TB (e.g. QUAL_RM_N or QUAL_RM_D) and make sure
       to reset the FP_STATUS to that default at the end of any TB that
       changes the default.  We could even (gasp) dynamiclly figure out
       what default would be most efficient given the running program.  */
    ctx.tb_rm = -1;
    /* Similarly for flush-to-zero.  */
    ctx.tb_ftz = -1;

    num_insns = 0;
    max_insns = tb->cflags & CF_COUNT_MASK;
    if (max_insns == 0)
        max_insns = CF_COUNT_MASK;

    gen_icount_start();
    do {
        if (unlikely(!QTAILQ_EMPTY(&env->breakpoints))) {
            QTAILQ_FOREACH(bp, &env->breakpoints, entry) {
                if (bp->pc == ctx.pc) {
                    gen_excp(&ctx, EXCP_DEBUG, 0);
                    break;
                }
            }
        }
        if (search_pc) {
            j = gen_opc_ptr - gen_opc_buf;
            if (lj < j) {
                lj++;
                while (lj < j)
                    gen_opc_instr_start[lj++] = 0;
            }
            gen_opc_pc[lj] = ctx.pc;
            gen_opc_instr_start[lj] = 1;
            gen_opc_icount[lj] = num_insns;
        }
        if (num_insns + 1 == max_insns && (tb->cflags & CF_LAST_IO))
            gen_io_start();
        num_insns++;

        if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP))) {
            tcg_gen_debug_insn_start(ctx.pc);
        }

        ret = translate_one(ctxp, &ctx.pc);

        /* If we reach a page boundary, are single stepping,
           or exhaust instruction count, stop generation.  */
        if (ret == NO_EXIT
            && ((ctx.pc & (TARGET_PAGE_SIZE - 1)) == 0
                || gen_opc_ptr >= gen_opc_end
                || num_insns >= max_insns
                || singlestep
                || env->singlestep_enabled)) {
            ret = EXIT_PC_STALE;
        }
    } while (ret == NO_EXIT);

    if (tb->cflags & CF_LAST_IO) {
        gen_io_end();
    }

    switch (ret) {
    case EXIT_GOTO_TB:
    case EXIT_NORETURN:
        break;
    case EXIT_PC_STALE:
        tcg_gen_movi_i64(cpu_pc, ctx.pc);
        /* FALLTHRU */
    case EXIT_PC_UPDATED:
        if (env->singlestep_enabled) {
            gen_excp_1(EXCP_DEBUG, 0);
        } else {
            tcg_gen_exit_tb(0);
        }
        break;
    default:
        abort();
    }

    gen_icount_end(tb, num_insns);
    *gen_opc_ptr = INDEX_op_end;
    if (search_pc) {
        j = gen_opc_ptr - gen_opc_buf;
        lj++;
        while (lj <= j)
            gen_opc_instr_start[lj++] = 0;
    } else {
        tb->size = ctx.pc - pc_start;
        tb->icount = num_insns;
    }

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("IN: %s\n", lookup_symbol(pc_start));
        log_target_disas(pc_start, ctx.pc - pc_start, 1);
        qemu_log("\n");
    }
#endif
}

void gen_intermediate_code (CPUState *env, struct TranslationBlock *tb)
{
    gen_intermediate_code_internal(env, tb, 0);
}

void gen_intermediate_code_pc (CPUState *env, struct TranslationBlock *tb)
{
    gen_intermediate_code_internal(env, tb, 1);
}

struct cpu_def_t {
    const char *name;
    int implver, amask;
};

static const struct cpu_def_t cpu_defs[] = {
    { "ev4",   IMPLVER_2106x, 0 },
    { "ev5",   IMPLVER_21164, 0 },
    { "ev56",  IMPLVER_21164, AMASK_BWX },
    { "pca56", IMPLVER_21164, AMASK_BWX | AMASK_MVI },
    { "ev6",   IMPLVER_21264, AMASK_BWX | AMASK_FIX | AMASK_MVI | AMASK_TRAP },
    { "ev67",  IMPLVER_21264, (AMASK_BWX | AMASK_FIX | AMASK_CIX
                               | AMASK_MVI | AMASK_TRAP | AMASK_PREFETCH), },
    { "ev68",  IMPLVER_21264, (AMASK_BWX | AMASK_FIX | AMASK_CIX
                               | AMASK_MVI | AMASK_TRAP | AMASK_PREFETCH), },
    { "21064", IMPLVER_2106x, 0 },
    { "21164", IMPLVER_21164, 0 },
    { "21164a", IMPLVER_21164, AMASK_BWX },
    { "21164pc", IMPLVER_21164, AMASK_BWX | AMASK_MVI },
    { "21264", IMPLVER_21264, AMASK_BWX | AMASK_FIX | AMASK_MVI | AMASK_TRAP },
    { "21264a", IMPLVER_21264, (AMASK_BWX | AMASK_FIX | AMASK_CIX
                                | AMASK_MVI | AMASK_TRAP | AMASK_PREFETCH), }
};

CPUAlphaState * cpu_alpha_init (const char *cpu_model)
{
    CPUAlphaState *env;
    int implver, amask, i, max;

    env = g_malloc0(sizeof(CPUAlphaState));
    cpu_exec_init(env);
    alpha_translate_init();
    tlb_flush(env, 1);

    /* Default to ev67; no reason not to emulate insns by default.  */
    implver = IMPLVER_21264;
    amask = (AMASK_BWX | AMASK_FIX | AMASK_CIX | AMASK_MVI
             | AMASK_TRAP | AMASK_PREFETCH);

    max = ARRAY_SIZE(cpu_defs);
    for (i = 0; i < max; i++) {
        if (strcmp (cpu_model, cpu_defs[i].name) == 0) {
            implver = cpu_defs[i].implver;
            amask = cpu_defs[i].amask;
            break;
        }
    }
    env->implver = implver;
    env->amask = amask;

#if defined (CONFIG_USER_ONLY)
    env->ps = PS_USER_MODE;
    cpu_alpha_store_fpcr(env, (FPCR_INVD | FPCR_DZED | FPCR_OVFD
                               | FPCR_UNFD | FPCR_INED | FPCR_DNOD));
#endif
    env->lock_addr = -1;
    env->fen = 1;

    qemu_init_vcpu(env);
    return env;
}

void restore_state_to_opc(CPUState *env, TranslationBlock *tb, int pc_pos)
{
    env->pc = gen_opc_pc[pc_pos];
}
