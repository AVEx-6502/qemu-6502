/*
 *  6502 emulation cpu translation for qemu.
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

#undef CPU6502_DEBUG_DISAS
#define CONFIG_SOFTFLOAT_INLINE

#ifdef CPU6502_DEBUG_DISAS
#  define LOG_DISAS(...) qemu_log_mask(CPU_LOG_TB_IN_ASM, ## __VA_ARGS__)
#else
#  define LOG_DISAS(...) do { } while (0)
#endif

typedef struct DisasContext DisasContext;
struct DisasContext {
    struct TranslationBlock *tb;
    CPU6502State *env;
    uint32_t pc;
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
static TCGv regAC;
static TCGv regX;
static TCGv regY;
static TCGv regSR;
static TCGv regSP;


#include "gen-icount.h"

static void cpu6502_translate_init(void)
{
    static int done_init = 0;

    if (done_init)
        return;

    cpu_env = tcg_global_reg_new_ptr(TCG_AREG0, "env");

    // Creating registers...
    regAC = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, ac), "AC");
    regX  = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState,  x),  "X");
    regY  = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState,  y),  "Y");

    regSR = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, sr), "SR");
    regSP = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, sp), "SP");

    cpu_pc = tcg_global_mem_new(TCG_AREG0,
                                offsetof(CPUState, pc), "pc");

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
    tcg_gen_movi_i32(cpu_pc, ctx->pc);
    gen_excp_1(exception, error_code);
    return EXIT_NORETURN;
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



/* Inlines for addressing modes...
 * First we have functions that load addresses.
 * Then we have functions that load values.
 */

/* Load address for "X,ind" addressing mode (looks like black magic but it's real!)...
 * In the black lang of Mordor (6502 assembly syntax), it's written ($BB,X).
 * In higher elvish (x86-like syntax), this means [[X+[ 0x?? ]]].
 * The function uses the same register for all intermediate value...
 *   NOTE: I think this has a bug... NOT TESTED!...
 */
static inline uint64_t gen_xind_mode_addr(TCGv reg, uint32_t code_addr)
{
    uint8_t zpg_imm = ldub_code(code_addr++);

    tcg_gen_movi_tl(reg, zpg_imm);
    tcg_gen_qemu_ld8u(reg, reg, 0);     // Inner []
    tcg_gen_add_tl(reg, reg, regX);     // Add X
    tcg_gen_qemu_ld16u(reg, reg, 0);    // [] around addition
    // Actual read is omited

    return code_addr;
}

static inline uint64_t gen_imm_mode(TCGv reg, uint32_t code_addr)
{
    uint8_t imm = ldub_code(code_addr++);
    tcg_gen_movi_tl(reg, imm);
    return code_addr;
}
static inline uint64_t gen_xind_mode(TCGv reg, uint32_t code_addr)
{
    code_addr = gen_xind_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);        // Outer []

    return code_addr;
}



static ExitStatus translate_one(DisasContext *ctx, uint32_t *paddr)
{
    fprintf(stderr, "A gerar: %"PRIX8", em %"PRIX16"\n", ldub_code(*paddr), (uint16_t)*paddr);
    uint8_t insn;

    // Decode opcode . . .
    switch(insn=ldub_code((*paddr)++)) {
        // Immediate loads
        case 0xA0: *paddr = gen_imm_mode(regY, *paddr);     return NO_EXIT;
        case 0xA2: *paddr = gen_imm_mode(regX, *paddr);     return NO_EXIT;
        case 0xA9: *paddr = gen_imm_mode(regAC, *paddr);    return NO_EXIT;


        // This is a phony instruction to print a char to stdout...
        case 0xFF:  // Write to stdout
            gen_helper_printchar(regAC);
            return NO_EXIT;
        case 0xFE:  // Read number from stdin
            gen_helper_getnum(regAC);
            return NO_EXIT;

        default:
        {
            TCGv_i32 tmp = tcg_temp_new_i32();
            TCGv_i32 tmp2 = tcg_temp_new_i32();
            tcg_gen_movi_i32(tmp, insn);
            tcg_gen_movi_i32(tmp2, *paddr-1);
            gen_helper_printstuff(tmp2, tmp);
            tcg_temp_free_i32(tmp2);
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
        tcg_gen_movi_i32(cpu_pc, ctx.pc);
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



CPU6502State * cpu_6502_init (const char *cpu_model)
{
    CPU6502State *env;

    env = g_malloc0(sizeof(CPU6502State));
    cpu_exec_init(env);
    cpu6502_translate_init();
    tlb_flush(env, 1);

    /* Default to ev67; no reason not to emulate insns by default.  */
    env->amask = (AMASK_BWX | AMASK_FIX | AMASK_CIX | AMASK_MVI
             | AMASK_TRAP | AMASK_PREFETCH);

#if defined (CONFIG_USER_ONLY)
    env->ps = PS_USER_MODE;
#endif
    env->fen = 1;

    qemu_init_vcpu(env);
    return env;
}

void restore_state_to_opc(CPUState *env, TranslationBlock *tb, int pc_pos)
{
    env->pc = gen_opc_pc[pc_pos];
}
