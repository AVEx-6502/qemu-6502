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

static TCGv regTMP;
static TCGv reg_last_res;


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

    cpu_pc = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, pc), "pc");

    regTMP = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, tmp), "TMP");
    reg_last_res = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, last_res), "LAST_RES");

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




/* Inlines for addressing modes...
 * First, we have self-descriptive get_from_code function.
 * Then, we have functions that load addresses.
 * Finally, we have functions that load values.
 */
static inline uint8_t get_from_code(uint32_t *code_addr)
{
    return ldub_code((*code_addr)++);
}
static inline uint16_t getw_from_code(uint32_t *code_addr)
{
    (*code_addr) += 2;
    return lduw_code(*code_addr - 2);
}

/* Load address for "X,ind" addressing mode (looks like black magic but it's real!)...
 * In the black lang of Mordor (6502 assembly syntax), it's written ($BB,X).
 * In higher elvish (x86-like syntax), this means [[X+[ 0x?? ]]].
 * The function uses the same register for all intermediate value...
 *   NOTE: I think this has a bug... NOT TESTED!...
 */
static inline uint32_t gen_abs_mode_addr(TCGv reg, uint32_t code_addr) {    // code_addr
    uint32_t base = getw_from_code(&code_addr);
    tcg_gen_movi_tl(reg, base);
    return code_addr;
}
static inline uint32_t gen_Xabs_mode_addr(TCGv reg, uint32_t code_addr) {   // X+code_addr
    uint32_t base = getw_from_code(&code_addr);
    tcg_gen_addi_tl(reg, regX, base);     // Add X
    tcg_gen_ext16u_tl(reg, reg);        // Truncate to 16 bits
    return code_addr;
}
static inline uint32_t gen_Yabs_mode_addr(TCGv reg, uint32_t code_addr) {   // Y+code_addr
    uint32_t base = getw_from_code(&code_addr);
    tcg_gen_addi_tl(reg, regY, base);     // Add Y
    tcg_gen_ext16u_tl(reg, reg);        // Truncate to 16 bits
    return code_addr;
}

static inline uint32_t gen_abs_mode(TCGv reg, uint32_t code_addr) {     // [code_addr]
    code_addr = gen_abs_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}
static inline uint32_t gen_Xabs_mode(TCGv reg, uint32_t code_addr) {    // [X+code_addr]
    code_addr = gen_Xabs_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}
static inline uint32_t gen_Yabs_mode(TCGv reg, uint32_t code_addr) {    // [Y+code_addr]
    code_addr = gen_Yabs_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}

static inline uint32_t gen_zero_page_mode_addr(TCGv reg, uint32_t code_addr) {  // code_addr (only 1 byte)
    uint32_t base = get_from_code(&code_addr);
    tcg_gen_movi_tl(reg, base);
    return code_addr;
}
static inline uint32_t gen_zero_page_X_mode_addr(TCGv reg, uint32_t code_addr) {    // X+code_addr (only 1 byte)
    uint32_t base = get_from_code(&code_addr);
    tcg_gen_addi_tl(reg, regX, base);     // Add X
    tcg_gen_ext8u_tl(reg, reg);   // Only lowest byte matters
    return code_addr;
}
static inline uint32_t gen_zero_page_Y_mode_addr(TCGv reg, uint32_t code_addr) {    // Y+code_addr (only 1 byte)
    uint32_t base = get_from_code(&code_addr);
    tcg_gen_addi_tl(reg, regY, base);     // Add Y
    tcg_gen_ext8u_tl(reg, reg);   // Only lowest byte matters
    return code_addr;
}

static inline uint32_t gen_zero_page_mode(TCGv reg, uint32_t code_addr) {  // [code_addr] (only 1 byte)
    code_addr = gen_zero_page_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}
static inline uint32_t gen_zero_page_X_mode(TCGv reg, uint32_t code_addr) {    // [X+code_addr] (only 1 byte)
    code_addr = gen_zero_page_X_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}
static inline uint32_t gen_zero_page_Y_mode(TCGv reg, uint32_t code_addr) {    // [Y+code_addr] (only 1 byte)
    code_addr = gen_zero_page_Y_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}

static inline uint32_t gen_indirect_X_addr(TCGv reg, uint32_t code_addr) {   // [X+code_addr] (2 bytes)
    // FIXME: When X+code_addr is 0xFF we should return 0xFF 0x00, currently 0xFF 0x100 is being returned.
    code_addr = gen_zero_page_X_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld16u(reg, reg, 0);
    return code_addr;
}
static inline uint32_t gen_indirect_X_mode(TCGv reg, uint32_t code_addr) {   // [[X+code_addr]]
    code_addr = gen_indirect_X_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}

static uint32_t gen_Y_indirect_addr(TCGv reg, uint32_t code_addr) {  // [code_addr]+Y (2 bytes)
    // FIXME: When X+code_addr is 0xFF we should return 0xFF 0x00, currently 0xFF 0x100 is being returned.
    code_addr = gen_zero_page_mode_addr(reg, code_addr);
    tcg_gen_qemu_ld16u(reg, reg, 0);
    tcg_gen_add_tl(reg, reg, regY);     // Add Y
    tcg_gen_ext16u_tl(reg, reg);        // Truncate to 16 bits
    return code_addr;
}
static uint32_t gen_Y_indirect_mode(TCGv reg, uint32_t code_addr) {  // [[code_addr]+Y]
    code_addr = gen_Y_indirect_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}


static ExitStatus translate_one(DisasContext *ctx, uint32_t *paddr)
{
    fprintf(stderr, "A gerar: %"PRIX8", em %"PRIX16"\n", ldub_code(*paddr), (uint16_t)*paddr);
    uint8_t insn;

    /* 6502 machine code is very very simple to parse. No need for black magic.
     * First comes the opcode, which is always 1 byte, and then comes either the
     * operand, or the clue to find it. The size and presence of any operand can
     * be rightly inferred from the opcode.
     */
    switch(insn = get_from_code(paddr)) {

        TCGv used_reg;
        uint32_t (*addr_func)(TCGv, uint32_t);

        /*
         *  Loads
         */

        // Immediate
        case 0xA0:  used_reg = regY;     goto load_imm_gen;
        case 0xA2:  used_reg = regX;     goto load_imm_gen;
        case 0xA9:  used_reg = regAC;    goto load_imm_gen;

        load_imm_gen: {
            tcg_gen_movi_tl(used_reg, get_from_code(paddr));
            tcg_gen_andi_tl(reg_last_res, reg_last_res, 0xFF00);    // Save result for Z and N flag computation
            tcg_gen_or_tl(reg_last_res, reg_last_res, used_reg);
            return NO_EXIT;
        }

        // Absolute
        case 0xAD:  used_reg = regAC;    addr_func = gen_abs_mode;           goto load_gen;
        case 0xAE:  used_reg = regX;     addr_func = gen_abs_mode;           goto load_gen;
        case 0xAC:  used_reg = regY;     addr_func = gen_abs_mode;           goto load_gen;
        // Absolute+X
        case 0xBD:  used_reg = regAC;    addr_func = gen_Xabs_mode;          goto load_gen;
        case 0xBC:  used_reg = regY;     addr_func = gen_Xabs_mode;          goto load_gen;
        // Absolute+Y
        case 0xB9:  used_reg = regAC;    addr_func = gen_Yabs_mode;          goto load_gen;
        case 0xBE:  used_reg = regX;     addr_func = gen_Yabs_mode;          goto load_gen;
        // Zero Page
        case 0xA5:  used_reg = regAC;    addr_func = gen_zero_page_mode;     goto load_gen;
        case 0xB5:  used_reg = regAC;    addr_func = gen_zero_page_X_mode;   goto load_gen;
        case 0xA6:  used_reg = regX;     addr_func = gen_zero_page_mode;     goto load_gen;
        case 0xB6:  used_reg = regX;     addr_func = gen_zero_page_Y_mode;   goto load_gen;
        case 0xA4:  used_reg = regY;     addr_func = gen_zero_page_mode;     goto load_gen;
        case 0xB4:  used_reg = regY;     addr_func = gen_zero_page_X_mode;   goto load_gen;
        // Indirect
        case 0xA1:  used_reg = regAC;    addr_func = gen_indirect_X_mode;    goto load_gen;
        case 0xB1:  used_reg = regAC;    addr_func = gen_Y_indirect_mode;    goto load_gen;

        load_gen: {
            *paddr = (*addr_func)(used_reg, *paddr);
            tcg_gen_andi_tl(reg_last_res, reg_last_res, 0xFF00);    // Save result for Z and N flag computation
            tcg_gen_or_tl(reg_last_res, reg_last_res, used_reg);
            return NO_EXIT;
        }

        /*
         *  Stores
         */

        // Absolute
        case 0x8D:  addr_func = gen_abs_mode_addr;      used_reg = regAC;          goto store_gen;
        case 0x8E:  addr_func = gen_abs_mode_addr;      used_reg = regX;           goto store_gen;
        case 0x8C:  addr_func = gen_abs_mode_addr;      used_reg = regY;           goto store_gen;

        // Absolute+?
        case 0x9D:  addr_func = gen_Xabs_mode_addr;      used_reg = regAC;         goto store_gen;
        case 0x99:  addr_func = gen_Yabs_mode_addr;      used_reg = regAC;         goto store_gen;

        // Zero-Page
        case 0x85:  addr_func = gen_zero_page_mode_addr;     used_reg = regAC;     goto store_gen;
        case 0x95:  addr_func = gen_zero_page_X_mode_addr;   used_reg = regAC;     goto store_gen;
        case 0x86:  addr_func = gen_zero_page_mode_addr;     used_reg = regX;      goto store_gen;
        case 0x96:  addr_func = gen_zero_page_Y_mode_addr;   used_reg = regX;      goto store_gen;
        case 0x84:  addr_func = gen_zero_page_mode_addr;     used_reg = regY;      goto store_gen;
        case 0x94:  addr_func = gen_zero_page_X_mode_addr;   used_reg = regY;      goto store_gen;
                                                                                   goto store_gen;
        // Indirect
        case 0x81:  addr_func = gen_indirect_X_addr;         used_reg = regAC;     goto store_gen;
        case 0x91:  addr_func = gen_Y_indirect_addr;         used_reg = regAC;     goto store_gen;

        store_gen: {
            *paddr = (*addr_func)(regTMP, *paddr);
            tcg_gen_qemu_st8(used_reg, regTMP, 0);
            return NO_EXIT;
        }

        /*
         *  Simple transfers between registers
         */
        TCGv src_reg;
        TCGv dst_reg;

        case 0x8A:      src_reg = regX;      dst_reg = regAC;       goto reg_transfer_gen;
        case 0x98:      src_reg = regY;      dst_reg = regAC;       goto reg_transfer_gen;
        case 0xA8:      src_reg = regAC;     dst_reg = regY;        goto reg_transfer_gen;
        case 0xAA:      src_reg = regAC;     dst_reg = regX;        goto reg_transfer_gen;
        case iTSX:      src_reg = regSP;     dst_reg = regX;        goto reg_transfer_gen;

        reg_transfer_gen: {
            tcg_gen_mov_tl(dst_reg, src_reg);
            tcg_gen_andi_tl(reg_last_res, reg_last_res, 0xFF00);    // Save result for Z and N flag computation
            tcg_gen_or_tl(reg_last_res, reg_last_res, dst_reg);
            return NO_EXIT;
        }

        // Special case: does not change the flags
        case iTXS: {
            tcg_gen_mov_tl(regSP, regX);
            return NO_EXIT;
        }

        /*
         *  Adds
         */

         // Immediate Add
        case 0x69: {
            tcg_gen_shri_tl(regTMP, reg_last_res, 8);   // Put carry flag in TMP reg
            tcg_gen_add_tl(regAC, regAC, regTMP);   // Add the carry
            tcg_gen_addi_tl(regAC, regAC, get_from_code(paddr));
            tcg_gen_mov_tl(reg_last_res, regAC);    // Save result for Z, N and C flag computation
            tcg_gen_ext8u_tl(regAC, regAC);         // Truncate to 8 bits

            // TODO: V flag
            return NO_EXIT;
        }

        case 0x6D:  addr_func = gen_abs_mode;           goto add_gen;
        case 0x65:  addr_func = gen_zero_page_mode;     goto add_gen;
        case 0x61:  addr_func = gen_indirect_X_mode;    goto add_gen;
        case 0x71:  addr_func = gen_Y_indirect_mode;    goto add_gen;
        case 0x75:  addr_func = gen_zero_page_X_mode;   goto add_gen;
        case 0x7D:  addr_func = gen_Xabs_mode;          goto add_gen;
        case 0x79:  addr_func = gen_Yabs_mode;          goto add_gen;

        add_gen: {
            tcg_gen_shri_tl(regTMP, reg_last_res, 8);   // Put carry flag in TMP reg
            tcg_gen_add_tl(regAC, regAC, regTMP);   // Add the carry
            *paddr = (*addr_func)(regTMP, *paddr);  // Get the value to add
            tcg_gen_add_tl(regAC, regAC, regTMP);   // Add it
            tcg_gen_mov_tl(reg_last_res, regAC);    // Save result for Z, N and C flag computation
            tcg_gen_ext8u_tl(regAC, regAC);         // Truncate to 8 bits

            // TODO: V flag
            return NO_EXIT;
        }



        // Jumps and branches
        case 0x4C:  tcg_gen_movi_tl(cpu_pc, getw_from_code(paddr));  return EXIT_PC_UPDATED;

        // Calls and rets
        case iJSR: {
            tcg_gen_movi_tl(regTMP, *paddr+1);  // The stack will receive the PC of the next instruction minus one.
            tcg_gen_addi_tl(regSP, regSP, -1+0x100);        // First, decrement SP, then write, then decrement again.
            tcg_gen_qemu_st16(regTMP, regSP, 0);            // This is because the stack of the 6502 is not word
            tcg_gen_addi_tl(regSP, regSP, -1-0x100);        // aligned, AND is decremented after write.
            tcg_gen_movi_tl(cpu_pc, getw_from_code(paddr)); // Jump to subroutine
            return EXIT_PC_UPDATED;
        }
        case iRTS: {
            tcg_gen_addi_tl(regSP, regSP, +1+0x100);
            tcg_gen_qemu_ld16u(cpu_pc, regSP, 0);
            tcg_gen_addi_tl(regSP, regSP, +1-0x100);
            tcg_gen_addi_tl(cpu_pc, cpu_pc, 1);
            tcg_gen_ext16u_tl(cpu_pc, regSP);        // Truncate to 16 bits
            return EXIT_PC_UPDATED;
        }

        // SEC
        case 0x38:  tcg_gen_ori_tl(reg_last_res, reg_last_res, 0x0100);     return NO_EXIT;

        // CLC
        case 0x18:  tcg_gen_andi_tl(reg_last_res, reg_last_res, 0x00FF);    return NO_EXIT;



        // NOP!
        case 0xEA:  return NO_EXIT;


        // These are phony instructions to work with the terminal...
        case 0xCF:  // Read number from stdin
            gen_helper_getnum(regAC);
            return NO_EXIT;
        case 0xDF:  // Read number from stdin
            gen_helper_printnum(regAC);
            return NO_EXIT;
        case 0xEF:  // Read char from stdin
            gen_helper_getchar(regAC);
            return NO_EXIT;
        case 0xFF:  // Write to stdout
            gen_helper_printchar(regAC);
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

    env->sr = 0x20;     // Flag in bit 5 is always 1
    env->last_res = 1;  // CPU must start with flags N and Z set to 0, so this can't be 0

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
