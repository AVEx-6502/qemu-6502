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

typedef struct DisasContext {
    struct TranslationBlock *tb;
    CPU6502State *env;
    uint32_t pc;
} DisasContext;

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

#define BRK_VEC     0xFFFE

// The following are the register variable as taken by TCG functions
static TCGv_ptr cpu_env;
static TCGv regPC;

// 6502 registers
static TCGv regAC;
static TCGv regX;
static TCGv regY;
static TCGv regSR;
static TCGv regSP;

static TCGv regTMP;

static TCGv reg_last_res_CN;
static TCGv reg_last_res_Z;
static TCGv reg_last_op1_V;
static TCGv reg_last_op2_V;
static TCGv reg_last_res_V;


#include "gen-icount.h"

static void cpu6502_translate_init(void)
{
    static int done_init = 0;

    if (done_init) return;

    cpu_env = tcg_global_reg_new_ptr(TCG_AREG0, "env");

    // Creating registers
    regAC = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, ac), "AC");
    regX  = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState,  x),  "X");
    regY  = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState,  y),  "Y");
    regSR = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, sr), "SR");
    regSP = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, sp), "SP");
    regPC = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, pc), "PC");

    regTMP = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, tmp), "TMP");
    reg_last_res_CN = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, last_res_CN), "LAST_RES_CN");
    reg_last_res_Z = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, last_res_Z), "LAST_RES_Z");
    reg_last_op1_V = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, last_op1_V), "LAST_OP1_V");
    reg_last_op2_V = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, last_op2_V), "LAST_OP2_V");
    reg_last_res_V = tcg_global_mem_new(TCG_AREG0, offsetof(CPUState, last_res_V), "LAST_RES_V");

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
    tcg_gen_movi_i32(regPC, ctx->pc);
    gen_excp_1(exception, error_code);
    return EXIT_NORETURN;
}

enum opcode {
    iADC_imm=0x69, iADC_abs=0x6D, iADC_zpg=0x65, iADC_Xind=0x61, iADC_indY=0x71, iADC_zpgX=0x75, iADC_absX=0x7D, iADC_absY=0x79,
    iSBC_imm=0xE9, iSBC_abs=0xED, iSBC_zpg=0xE5, iSBC_Xind=0xE1, iSBC_indY=0xF1, iSBC_zpgX=0xF5, iSBC_absX=0xFD, iSBC_absY=0xF9,
    iCMP_imm=0xC9, iCMP_abs=0xCD, iCMP_zpg=0xC5, iCMP_Xind=0xC1, iCMP_indY=0xD1, iCMP_zpgX=0xD5, iCMP_absX=0xDD, iCMP_absY=0xD9,
    iEOR_imm=0x49, iEOR_abs=0x4D, iEOR_zpg=0x45, iEOR_Xind=0x41, iEOR_indY=0x51, iEOR_zpgX=0x55, iEOR_absX=0x5D, iEOR_absY=0x59,
    iAND_imm=0x29, iAND_abs=0x2D, iAND_zpg=0x25, iAND_Xind=0x21, iAND_indY=0x31, iAND_zpgX=0x35, iAND_absX=0x3D, iAND_absY=0x39,
    iORA_imm=0x09, iORA_abs=0x0D, iORA_zpg=0x05, iORA_Xind=0x01, iORA_indY=0x11, iORA_zpgX=0x15, iORA_absX=0x1D, iORA_absY=0x19,

    iLDA_imm=0xA9, iLDA_abs=0xAD, iLDA_zpg=0xA5, iLDA_Xind=0xA1, iLDA_indY=0xB1, iLDA_zpgX=0xB5, iLDA_absX=0xBD, iLDA_absY=0xB9,
    iLDX_imm=0xA2, iLDX_abs=0xAE, iLDX_zpg=0xA6, iLDX_zpgY=0xB6, iLDX_absY=0xBE,
    iLDY_imm=0xA0, iLDY_abs=0xAC, iLDY_zpg=0xA4, iLDY_zpgX=0xB4, iLDY_absX=0xBC,

    iSTA_abs=0x8D, iSTA_absX=0x9D, iSTA_absY=0x99, iSTA_zpg=0x85, iSTA_zpgX=0x95, iSTA_Xind=0x81, iSTA_indY=0x91,
    iSTX_abs=0x8E, iSTX_zpg=0x86, iSTX_zpgY=0x96,
    iSTY_abs=0x8C, iSTY_zpg=0x84, iSTY_zpgX=0x94,

    iASL_A=0x0A, iASL_zpg=0x06, iASL_zpgX=0x16, iASL_abs=0x0E, iASL_absX=0x1E,
    iLSR_A=0x4A, iLSR_zpg=0x46, iLSR_zpgX=0x56, iLSR_abs=0x4E, iLSR_absX=0x5E,
    iROL_A=0x2A, iROL_zpg=0x26, iROL_zpgX=0x36, iROL_abs=0x2E, iROL_absX=0x3E,
    iROR_A=0x6A, iROR_zpg=0x66, iROR_zpgX=0x76, iROR_abs=0x6E, iROR_absX=0x7E,

    iJMP_abs = 0x4C, iJMP_ind = 0x6C,

    iCPX_imm = 0xE0, iCPX_abs = 0xEC, iCPX_zpg = 0xE4,
    iCPY_imm = 0xC0, iCPY_abs = 0xCC, iCPY_zpg = 0xC4,

    iTXA = 0x8A, iTYA = 0x98, iTAY = 0xA8, iTAX = 0xAA, iTXS = 0x9A, iTSX = 0xBA,

    iPHA = 0x48,
    iPHP = 0x08,
    iPLA = 0x68,
    iPLP = 0x28,

    iJSR = 0x20, iRTS = 0x60,
    iBRK = 0x00, iRTI = 0x40,

    iBPL=0x10, iBMI=0x30, iBCC=0x90, iBCS=0xB0, iBNE=0xD0, iBEQ=0xF0, iBVC = 0x50, iBVS = 0x70,

    iINX = 0xE8, iINY = 0xC8, iINC_abs = 0xEE, iINC_zpg = 0xE6, iINC_zpgX = 0xF6, iINC_absX = 0xFE,
    iDEX = 0xCA, iDEY = 0x88, iDEC_abs = 0xCE, iDEC_zpg = 0xC6, iDEC_zpgX = 0xD6, iDEC_absX = 0xDE,

    iBIT_abs = 0x2C, iBIT_zpg = 0x24,

    iCLC = 0x18, iSEC = 0x38,
    iCLV = 0xB8,
    iCLD = 0xD8, iSED = 0xF8,
    iCLI = 0x58, iSEI = 0x78,

    iNOP = 0xEA,

    // Undocumented opcodes
    iLAX_zpg = 0xA7, iLAX_zpgY = 0xB7, iLAX_abs = 0xAF, iLAX_Xind = 0xA3, iLAX_indY = 0xB3, iLAX_absY = 0xBF,
    iSAX_zpg = 0x87, iSAX_zpgY = 0x97, iSAX_abs = 0x8F, iSAX_Xind = 0x83,
};


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


static inline uint32_t gen_abs_mode_addr(TCGv reg, uint32_t code_addr) {    // code_addr
    uint32_t base = getw_from_code(&code_addr);
    tcg_gen_movi_tl(reg, base);
    return code_addr;
}
static inline uint32_t gen_Xabs_mode_addr(TCGv reg, uint32_t code_addr) {   // X+code_addr
    uint32_t base = getw_from_code(&code_addr);
    tcg_gen_addi_tl(reg, regX, base);    // Add X
    tcg_gen_ext16u_tl(reg, reg);        // Truncate to 16 bits
    return code_addr;
}
static inline uint32_t gen_Yabs_mode_addr(TCGv reg, uint32_t code_addr) {   // Y+code_addr
    uint32_t base = getw_from_code(&code_addr);
    tcg_gen_addi_tl(reg, regY, base);    // Add Y
    tcg_gen_ext16u_tl(reg, reg);        // Truncate to 16 bits
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

/* Load address for "X,ind" addressing mode (looks like black magic but it's real!)...
 * In the black lang of Mordor (6502 assembly syntax), it's written ($BB,X).
 * In higher elvish (x86-like syntax), this means sth like [[X+[ 0x?? ]]].
 * The function uses the same register for all intermediate values...
 */
static inline uint32_t gen_indirect_X_addr(TCGv reg, uint32_t code_addr) {   // [X+code_addr] (2 bytes)
    // NOTE1: X+code_addr is truncated to 1 byte
    // NOTE2: When X+code_addr == FF, the result will be from 0xFF 0x00 and not 0xFF 0x100
    code_addr = gen_zero_page_X_mode_addr(reg, code_addr);  // reg = X + code_addr
    TCGv reg_temp = tcg_temp_new();
    tcg_gen_qemu_ld8u(reg_temp, reg, 0);    // Put first byte in reg_temp, reg_temp = [X+code_addr] & 0x00FF
    tcg_gen_addi_tl(reg, reg, 1);           // Calculate address of second byte
    tcg_gen_ext8u_tl(reg, reg);
    tcg_gen_qemu_ld8u(reg, reg, 0);         // Put second byte in reg
    tcg_gen_shli_tl(reg, reg, 8);
    tcg_gen_or_tl(reg, reg, reg_temp);      // Now join both
    tcg_temp_free(reg_temp);
    return code_addr;
}
static uint32_t gen_Y_indirect_addr(TCGv reg, uint32_t code_addr) {  // [code_addr]+Y (2 bytes)
    // NOTE: When code_addr == 0xFF, the result will be from 0xFF 0x00 and not 0xFF 0x100
    uint32_t base = get_from_code(&code_addr);
    tcg_gen_movi_tl(reg, base);
    if(base != 0xFF) {  // Easy case
        tcg_gen_qemu_ld16u(reg, reg, 0);
    } else {    // Page boundary, complex case
        TCGv reg_temp = tcg_temp_new();
        tcg_gen_qemu_ld8u(reg_temp, reg, 0);    // Put first byte in reg_temp, reg_temp = [code_addr] & 0xFF
        tcg_gen_movi_tl(reg, 0);                // Put second byte in reg
        tcg_gen_qemu_ld8u(reg, reg, 0);
        tcg_gen_shli_tl(reg, reg, 8);
        tcg_gen_or_tl(reg, reg, reg_temp);      // Join both
        tcg_temp_free(reg_temp);
    }
    tcg_gen_add_tl(reg, reg, regY);     // Add Y
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
static inline uint32_t gen_indirect_X_mode(TCGv reg, uint32_t code_addr) {   // [[X+code_addr]]
    code_addr = gen_indirect_X_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}
static uint32_t gen_Y_indirect_mode(TCGv reg, uint32_t code_addr) {  // [[code_addr]+Y]
    code_addr = gen_Y_indirect_addr(reg, code_addr);
    tcg_gen_qemu_ld8u(reg, reg, 0);
    return code_addr;
}



static void gen_V_flag(TCGv reg) {
    // (OP1 ^ ~OP2) & (OP1 ^ RES) & 0x80
    tcg_gen_not_tl(reg, reg_last_op2_V);
    tcg_gen_xor_tl(reg, reg_last_op1_V, reg);
    TCGv temp = tcg_temp_new();
    tcg_gen_xor_tl(temp, reg_last_op1_V, reg_last_res_V);
    tcg_gen_and_tl(reg, reg, temp);
    tcg_temp_free(temp);
    tcg_gen_andi_tl(reg, reg, 0x80);
}



static void gen_iPHP(void)
{
    // Calculate flags register
    int lbl_notZ = gen_new_label();
    tcg_gen_shri_tl(regTMP, reg_last_res_CN, 8);     // Carry flag
    tcg_gen_brcondi_tl(TCG_COND_NE, reg_last_res_Z, 0, lbl_notZ);    // Zero flag
    tcg_gen_ori_tl(regTMP, regTMP, 0x02);
    gen_set_label(lbl_notZ);
    TCGv flags = tcg_temp_new();
    gen_V_flag(flags);     // Overflow flag
    tcg_gen_shri_tl(flags, flags, 1);
    tcg_gen_or_tl(flags, flags, regTMP);
    tcg_gen_andi_tl(regTMP, reg_last_res_CN, 0x80);     // Negative flag
    tcg_gen_or_tl(flags, flags, regTMP);
    tcg_gen_ori_tl(flags, flags, 0x30);     // Unused bit and Break flag = 1

    // Apply D and I flags to the value being pushed
    tcg_gen_andi_tl(regSR, regSR, 0x0C);    // Only D,I
    tcg_gen_or_tl(flags, flags, regSR);

    // Push flags register into the stack
    tcg_gen_ori_tl(regSP, regSP, 0x100);
    tcg_gen_qemu_st8(flags, regSP, 0);
    tcg_gen_subi_tl(regSP, regSP, 0x100+1);
    tcg_gen_ext8u_tl(regSP, regSP);

    tcg_temp_free(flags);
}

static void gen_iPLP(void)
{
    // Get byte from top of the stack
    tcg_gen_addi_tl(regSP, regSP, 1);
    tcg_gen_ori_tl(regSP, regSP, 0x100);    // By doing the sum this way we ensure the instruction respects bounds
    tcg_gen_qemu_ld8u(regTMP, regSP, 0);
    tcg_gen_ext8u_tl(regSP, regSP);         // No need to do bounds cheking again

    // Save the flags in register (this applies only to D,I flags)
    tcg_gen_mov_tl(regSR, regTMP);

    // Update the flags
    int lbl_notV = gen_new_label();
    int lbl_calcC = gen_new_label();
    tcg_gen_mov_tl(reg_last_res_CN, regTMP);    // Negative
    tcg_gen_andi_tl(reg_last_res_Z, regTMP, 0x02); // Zero
    tcg_gen_xori_tl(reg_last_res_Z, reg_last_res_Z, 0x02);
    tcg_gen_andi_tl(regTMP, regTMP, 0x41);      // Keep only V and C
    tcg_gen_brcondi_tl(TCG_COND_LTU, regTMP, 0x40, lbl_notV);

    // V == 1
    tcg_gen_movi_tl(reg_last_op1_V, 0);
    tcg_gen_movi_tl(reg_last_op2_V, 0);
    tcg_gen_movi_tl(reg_last_res_V, 0xFF);
    tcg_gen_br(lbl_calcC);

    // V == 0
    gen_set_label(lbl_notV);
    tcg_gen_mov_tl(reg_last_op2_V, reg_last_res_V);

    // Update the carry
    gen_set_label(lbl_calcC);
    tcg_gen_andi_tl(regTMP, regTMP, 0x01);
    tcg_gen_shli_tl(regTMP, regTMP, 8);
    tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regTMP);
}


// PPC means Push PC
static void gen_PPC(uint16_t ret_addr)
{
    tcg_gen_ori_tl(regSP, regSP, 0x100);

    tcg_gen_movi_tl(regTMP, (ret_addr)>>8);
    tcg_gen_qemu_st8(regTMP, regSP, 0);
    tcg_gen_subi_tl(regSP, regSP, 1);
    tcg_gen_ori_tl(regSP, regSP, 0x100);        // Fix the possible 8-bit wrap-around
    tcg_gen_movi_tl(regTMP, (ret_addr)&0xFF);
    tcg_gen_qemu_st8(regTMP, regSP, 0);

    tcg_gen_subi_tl(regSP, regSP, 1);
    tcg_gen_ext8u_tl(regSP, regSP);
}


static void gen_iRTS(int add_one)
{
    tcg_gen_addi_tl(regSP, regSP, 1);
    tcg_gen_ori_tl(regSP, regSP, 0x100);

    tcg_gen_qemu_ld8u(regPC, regSP, 0);     // Low byte
    tcg_gen_addi_tl(regSP, regSP, 1);
    tcg_gen_ext8u_tl(regSP, regSP);
    tcg_gen_ori_tl(regSP, regSP, 0x100);    // Fix the possible wrap-around
    tcg_gen_qemu_ld8u(regTMP, regSP, 0);    // High byte
    tcg_gen_shli_tl(regTMP, regTMP, 8);
    tcg_gen_or_tl(regPC, regPC, regTMP);

    tcg_gen_ext8u_tl(regSP, regSP);

    if(add_one) {
        tcg_gen_addi_tl(regPC, regPC, 1);
    }
    tcg_gen_ext16u_tl(regPC, regPC);        // Truncate to 16 bits
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
        case iLDA_imm:  used_reg = regAC;    goto load_imm_gen;
        case iLDX_imm:  used_reg = regX;     goto load_imm_gen;
        case iLDY_imm:  used_reg = regY;     goto load_imm_gen;

        load_imm_gen: {
            tcg_gen_movi_tl(used_reg, get_from_code(paddr));
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, used_reg);
            tcg_gen_mov_tl(reg_last_res_Z, used_reg);                     // Save result for Z flag computation
            return NO_EXIT;
        }

        // Absolute
        case iLDA_abs:   used_reg = regAC;    addr_func = gen_abs_mode;           goto load_gen;
        case iLDX_abs:   used_reg = regX;     addr_func = gen_abs_mode;           goto load_gen;
        case iLDY_abs:   used_reg = regY;     addr_func = gen_abs_mode;           goto load_gen;
        // Absolute+X
        case iLDA_absX:  used_reg = regAC;    addr_func = gen_Xabs_mode;          goto load_gen;
        case iLDY_absX:  used_reg = regY;     addr_func = gen_Xabs_mode;          goto load_gen;
        // Absolute+Y
        case iLDA_absY:  used_reg = regAC;    addr_func = gen_Yabs_mode;          goto load_gen;
        case iLDX_absY:  used_reg = regX;     addr_func = gen_Yabs_mode;          goto load_gen;
        // Zero Page
        case iLDA_zpg:   used_reg = regAC;    addr_func = gen_zero_page_mode;     goto load_gen;
        case iLDX_zpg:   used_reg = regX;     addr_func = gen_zero_page_mode;     goto load_gen;
        case iLDY_zpg:   used_reg = regY;     addr_func = gen_zero_page_mode;     goto load_gen;
        case iLDA_zpgX:  used_reg = regAC;    addr_func = gen_zero_page_X_mode;   goto load_gen;
        case iLDY_zpgX:  used_reg = regY;     addr_func = gen_zero_page_X_mode;   goto load_gen;
        case iLDX_zpgY:  used_reg = regX;     addr_func = gen_zero_page_Y_mode;   goto load_gen;
        // Indirect
        case iLDA_Xind:  used_reg = regAC;    addr_func = gen_indirect_X_mode;    goto load_gen;
        case iLDA_indY:  used_reg = regAC;    addr_func = gen_Y_indirect_mode;    goto load_gen;

        load_gen: {
            *paddr = (*addr_func)(used_reg, *paddr);
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, used_reg);
            tcg_gen_mov_tl(reg_last_res_Z, used_reg);                     // Save result for Z flag computation
            return NO_EXIT;
        }

        /*
         *  Stores
         */

        // Absolute
        case iSTA_abs:   addr_func = gen_abs_mode_addr;           used_reg = regAC;     goto store_gen;
        case iSTX_abs:   addr_func = gen_abs_mode_addr;           used_reg = regX;      goto store_gen;
        case iSTY_abs:   addr_func = gen_abs_mode_addr;           used_reg = regY;      goto store_gen;
        // Absolute+?
        case iSTA_absX:  addr_func = gen_Xabs_mode_addr;          used_reg = regAC;     goto store_gen;
        case iSTA_absY:  addr_func = gen_Yabs_mode_addr;          used_reg = regAC;     goto store_gen;
        // Zero-Page
        case iSTA_zpg:   addr_func = gen_zero_page_mode_addr;     used_reg = regAC;     goto store_gen;
        case iSTX_zpg:   addr_func = gen_zero_page_mode_addr;     used_reg = regX;      goto store_gen;
        case iSTY_zpg:   addr_func = gen_zero_page_mode_addr;     used_reg = regY;      goto store_gen;
        case iSTA_zpgX:  addr_func = gen_zero_page_X_mode_addr;   used_reg = regAC;     goto store_gen;
        case iSTY_zpgX:  addr_func = gen_zero_page_X_mode_addr;   used_reg = regY;      goto store_gen;
        case iSTX_zpgY:  addr_func = gen_zero_page_Y_mode_addr;   used_reg = regX;      goto store_gen;
        // Indirect
        case iSTA_Xind:  addr_func = gen_indirect_X_addr;         used_reg = regAC;     goto store_gen;
        case iSTA_indY:  addr_func = gen_Y_indirect_addr;         used_reg = regAC;     goto store_gen;

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

        case iTXA:      src_reg = regX;      dst_reg = regAC;       goto reg_transfer_gen;
        case iTYA:      src_reg = regY;      dst_reg = regAC;       goto reg_transfer_gen;
        case iTAY:      src_reg = regAC;     dst_reg = regY;        goto reg_transfer_gen;
        case iTAX:      src_reg = regAC;     dst_reg = regX;        goto reg_transfer_gen;
        case iTSX:      src_reg = regSP;     dst_reg = regX;        goto reg_transfer_gen;

        reg_transfer_gen: {
            tcg_gen_mov_tl(dst_reg, src_reg);
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, dst_reg);
            tcg_gen_mov_tl(reg_last_res_Z, dst_reg);                      // Save result for Z flag computation
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
        case iADC_imm: {
            int lbl_decimal = gen_new_label();
            int lbl_cont = gen_new_label();

            uint8_t value = get_from_code(paddr);       // Get the value to add

            // See if decimal mode on:
            tcg_gen_andi_tl(regTMP, regSR, flagD);
            tcg_gen_brcondi_tl(TCG_COND_NE, regTMP, 0, lbl_decimal);

            {
                // Code for "binary" mode
                tcg_gen_mov_tl(reg_last_op1_V, regAC);      // Save operand 1 (V flag)
                tcg_gen_movi_tl(reg_last_op2_V, value);     // Save operand 2 (V flag)
                tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);     // Get the carry
                tcg_gen_add_tl(reg_last_res_CN, regAC, reg_last_res_CN);  // Add the carry
                tcg_gen_addi_tl(reg_last_res_CN, reg_last_res_CN, value);  // Add the value
                tcg_gen_ext8u_tl(regAC, reg_last_res_CN);         // Truncate to 8 bits
                tcg_gen_mov_tl(reg_last_res_Z, regAC);
                tcg_gen_mov_tl(reg_last_res_V, regAC);      // Save result (V flag)
            }
            tcg_gen_br(lbl_cont);

            gen_set_label(lbl_decimal);
            {
                TCGv lo = tcg_temp_local_new();
                TCGv hi = tcg_temp_local_new();
                int no_adjust_lo = gen_new_label();
                int no_adjust_hi = gen_new_label();

                // Low nibble
                tcg_gen_andi_tl(lo, regAC, 0x0F);
                tcg_gen_addi_tl(lo, lo, value & 0x0F);
                tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);     // Get the carry
                tcg_gen_add_tl(lo, lo, reg_last_res_CN);

                // High nibble
                tcg_gen_andi_tl(hi, regAC, 0xF0);
                tcg_gen_addi_tl(hi, hi, value & 0xF0);

                // Compute the zero flag
                tcg_gen_add_tl(reg_last_res_Z, hi, lo);
                tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_Z);

                // See if we need to adjust the low nibble
                tcg_gen_brcondi_tl(TCG_COND_LT, lo, 10, no_adjust_lo);
                tcg_gen_addi_tl(lo, lo, 6);
                //tcg_gen_andi_tl(lo, 0x0F);
                tcg_gen_addi_tl(hi, hi, 16);
                gen_set_label(no_adjust_lo);

                // Negative flag
                tcg_gen_andi_tl(reg_last_res_CN, hi, 0x0080);   // Carry flag is not valid under this formula

                // Overflow flag
                tcg_gen_mov_tl(reg_last_op1_V, regAC);      // Save operand 1 (V flag)
                tcg_gen_movi_tl(reg_last_op2_V, value);     // Save operand 2 (V flag)
                tcg_gen_mov_tl(reg_last_res_V, hi);         // Save result (V flag)

                // See if we need to adjust the high nibble
                tcg_gen_brcondi_tl(TCG_COND_LT, hi, 0xA0, no_adjust_hi);
                tcg_gen_addi_tl(hi, hi, 0x60);
                gen_set_label(no_adjust_hi);

                // Compute final result
                tcg_gen_andi_tl(regAC, lo, 0x0F);
                tcg_gen_add_tl(regAC, regAC, hi);
                tcg_gen_ext8u_tl(regAC, regAC);

                // Carry flag
                tcg_gen_setcondi_tl(TCG_COND_GEU, hi, hi, 0x0100);
                tcg_gen_shli_tl(hi, hi, 8);
                tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, hi);

                tcg_temp_free(hi);
                tcg_temp_free(lo);
            }

            gen_set_label(lbl_cont);
            return NO_EXIT;
        }

        case iADC_abs:   addr_func = gen_abs_mode;           goto add_gen;
        case iADC_zpg:   addr_func = gen_zero_page_mode;     goto add_gen;
        case iADC_Xind:  addr_func = gen_indirect_X_mode;    goto add_gen;
        case iADC_indY:  addr_func = gen_Y_indirect_mode;    goto add_gen;
        case iADC_zpgX:  addr_func = gen_zero_page_X_mode;   goto add_gen;
        case iADC_absX:  addr_func = gen_Xabs_mode;          goto add_gen;
        case iADC_absY:  addr_func = gen_Yabs_mode;          goto add_gen;

        add_gen: {
            TCGv decimal_decide = tcg_temp_local_new();
            int lbl_decimal = gen_new_label();
            int lbl_cont = gen_new_label();

            *paddr = (*addr_func)(regTMP, *paddr);      // Get the value to add

            // See if decimal mode on:
            tcg_gen_andi_tl(decimal_decide, regSR, flagD);
            tcg_gen_brcondi_tl(TCG_COND_NE, decimal_decide, 0, lbl_decimal);

            {
                tcg_gen_mov_tl(reg_last_op1_V, regAC);      // Save operand 1 (V flag)
                tcg_gen_mov_tl(reg_last_op2_V, regTMP);     // Save operand 2 (V flag)
                tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);     // Get the carry
                tcg_gen_add_tl(reg_last_res_CN, regAC, reg_last_res_CN);  // Add the carry
                tcg_gen_add_tl(reg_last_res_CN, reg_last_res_CN, regTMP); // Add the value
                tcg_gen_ext8u_tl(regAC, reg_last_res_CN);         // Truncate to 8 bits
                tcg_gen_mov_tl(reg_last_res_Z, regAC);
                tcg_gen_mov_tl(reg_last_res_V, regAC);      // Save result (V flag)
            }
            tcg_gen_br(lbl_cont);

            gen_set_label(lbl_decimal);
            {
                TCGv tmp2 = tcg_temp_local_new();
                TCGv lo = tcg_temp_local_new();
                TCGv hi = tcg_temp_local_new();
                int no_adjust_lo = gen_new_label();
                int no_adjust_hi = gen_new_label();

                // Low nibble
                tcg_gen_andi_tl(lo, regAC, 0x0F);
                tcg_gen_andi_tl(tmp2, regTMP, 0x0F);
                tcg_gen_add_tl(lo, lo, tmp2);
                tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);     // Get the carry
                tcg_gen_add_tl(lo, lo, reg_last_res_CN);

                // High nibble
                tcg_gen_andi_tl(hi, regAC, 0xF0);
                tcg_gen_andi_tl(tmp2, regTMP, 0xF0);
                tcg_gen_add_tl(hi, hi, tmp2);

                // Compute the zero flag
                tcg_gen_add_tl(reg_last_res_Z, hi, lo);
                tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_Z);

                // See if we need to adjust the low nibble
                tcg_gen_brcondi_tl(TCG_COND_LTU, lo, 10, no_adjust_lo);
                tcg_gen_addi_tl(lo, lo, 6);
                tcg_gen_addi_tl(hi, hi, 16);
                gen_set_label(no_adjust_lo);

                // Negative flag
                tcg_gen_andi_tl(reg_last_res_CN, hi, 0x0080);   // Carry flag is not valid under this formula

                // Overflow flag
                tcg_gen_mov_tl(reg_last_op1_V, regAC);      // Save operand 1 (V flag)
                tcg_gen_mov_tl(reg_last_op2_V, regTMP);     // Save operand 2 (V flag)
                tcg_gen_mov_tl(reg_last_res_V, hi);         // Save result (V flag)

                // See if we need to adjust the high nibble
                tcg_gen_brcondi_tl(TCG_COND_LTU, hi, 0xA0, no_adjust_hi);
                tcg_gen_addi_tl(hi, hi, 0x60);
                gen_set_label(no_adjust_hi);

                // Compute final result
                tcg_gen_andi_tl(regAC, lo, 0x0F);
                tcg_gen_or_tl(regAC, regAC, hi);
                tcg_gen_ext8u_tl(regAC, regAC);

                // Carry flag
                tcg_gen_setcondi_tl(TCG_COND_GEU, hi, hi, 0x0100);
                tcg_gen_shli_tl(hi, hi, 8);
                tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, hi);

                tcg_temp_free(hi);
                tcg_temp_free(lo);
                tcg_temp_free(tmp2);
            }

            gen_set_label(lbl_cont);
            tcg_temp_free(decimal_decide);
            return NO_EXIT;
        }


        /*
         *  Subtracts
         *   - NOTE: A - M - ~C == A + ~M + C, because Carry is Borrow in Subtract
         */

        // Immediate Subtract
        case iSBC_imm: {
            int lbl_decimal = gen_new_label();
            int lbl_cont = gen_new_label();

            uint8_t value = get_from_code(paddr) ^ 0xFF;

            // See if decimal mode on:
            tcg_gen_andi_tl(regTMP, regSR, flagD);
            tcg_gen_brcondi_tl(TCG_COND_NE, regTMP, 0, lbl_decimal);

            {
                // Code for "binary" mode
                tcg_gen_mov_tl(reg_last_op1_V, regAC);      // Save operand 1 (V flag)
                tcg_gen_movi_tl(reg_last_op2_V, value);     // Save operand 2 (V flag)
                tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);      // Get the carry
                tcg_gen_add_tl(reg_last_res_CN, regAC, reg_last_res_CN);   // Add the carry
                tcg_gen_addi_tl(reg_last_res_CN, reg_last_res_CN, value);  // Add ~M
                tcg_gen_ext8u_tl(regAC, reg_last_res_CN);             // Truncate to 8 bits
                tcg_gen_mov_tl(reg_last_res_Z, regAC);
                tcg_gen_mov_tl(reg_last_res_V, regAC);      // Save result (V flag)
            }
            tcg_gen_br(lbl_cont);

            gen_set_label(lbl_decimal);
            {
                // Code for "BCD" mode
                tcg_gen_mov_tl(regTMP, reg_last_res_CN);    // Save the old Carry value

                // There follows the code to compute the flgas, which is just like in binary mode...
                tcg_gen_mov_tl(reg_last_op1_V, regAC);      // Save operand 1 (V flag)
                tcg_gen_movi_tl(reg_last_op2_V, value);     // Save operand 2 (V flag)
                tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);      // Get the carry
                tcg_gen_add_tl(reg_last_res_CN, regAC, reg_last_res_CN);   // Add the carry
                tcg_gen_addi_tl(reg_last_res_CN, reg_last_res_CN, value);  // Add ~M
                tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_CN);   // Truncate to 8 bits
                tcg_gen_mov_tl(reg_last_res_V, reg_last_res_Z);      // Save result (V flag)

                // Now compute the result
                value = value^0xFF;         // Get the real value back again...
                TCGv lo = tcg_temp_local_new();
                TCGv hi = tcg_temp_local_new();
                int no_adjust_lo = gen_new_label();
                int no_adjust_hi = gen_new_label();

                // Low nibble
                tcg_gen_andi_tl(lo, regAC, 0x0F);
                tcg_gen_subi_tl(lo, lo, (value & 0x0F)+1);
                tcg_gen_shri_tl(regTMP, regTMP, 8);     // Get the carry
                tcg_gen_add_tl(lo, lo, regTMP);

                // High nibble
                tcg_gen_andi_tl(hi, regAC, 0xF0);
                tcg_gen_subi_tl(hi, hi, value & 0xF0);

                // See if we need to adjust the low nibble
                tcg_gen_brcondi_tl(TCG_COND_GE, lo, 0, no_adjust_lo);
                tcg_gen_subi_tl(lo, lo, 6);
                tcg_gen_subi_tl(hi, hi, 16);
                gen_set_label(no_adjust_lo);

                // See if we need to adjust the high nibble
                tcg_gen_brcondi_tl(TCG_COND_GE, hi, 0, no_adjust_hi);
                tcg_gen_subi_tl(hi, hi, 0x60);
                gen_set_label(no_adjust_hi);

                // Compute final result
                tcg_gen_andi_tl(regAC, lo, 0x0F);
                tcg_gen_or_tl(regAC, regAC, hi);
                tcg_gen_ext8u_tl(regAC, regAC);

                tcg_temp_free(hi);
                tcg_temp_free(lo);
            }

            gen_set_label(lbl_cont);
            return NO_EXIT;
        }

        case iSBC_abs:   addr_func = gen_abs_mode;           goto sub_gen;
        case iSBC_absX:  addr_func = gen_Xabs_mode;          goto sub_gen;
        case iSBC_absY:  addr_func = gen_Yabs_mode;          goto sub_gen;
        case iSBC_zpg:   addr_func = gen_zero_page_mode;     goto sub_gen;
        case iSBC_zpgX:  addr_func = gen_zero_page_X_mode;   goto sub_gen;
        case iSBC_Xind:  addr_func = gen_indirect_X_mode;    goto sub_gen;
        case iSBC_indY:  addr_func = gen_Y_indirect_mode;    goto sub_gen;

        sub_gen: {
            TCGv tmp2 = tcg_temp_local_new();
            int lbl_decimal = gen_new_label();
            int lbl_cont = gen_new_label();

            *paddr = (*addr_func)(regTMP, *paddr);      // Get the value to add
            tcg_gen_xori_tl(regTMP, regTMP, 0x00FF);    // M = ~M, we only want the first byte

            // See if decimal mode on:
            tcg_gen_andi_tl(tmp2, regSR, flagD);
            tcg_gen_brcondi_tl(TCG_COND_NE, tmp2, 0, lbl_decimal);

            {
                tcg_gen_mov_tl(reg_last_op1_V, regAC);      // Save operand 1 (V flag)
                tcg_gen_mov_tl(reg_last_op2_V, regTMP);     // Save operand 2 (V flag)
                tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);     // Get the carry
                tcg_gen_add_tl(reg_last_res_CN, regAC, reg_last_res_CN);  // Add the carry
                tcg_gen_add_tl(reg_last_res_CN, reg_last_res_CN, regTMP); // Add the value
                tcg_gen_ext8u_tl(regAC, reg_last_res_CN);      // Truncate to 8 bits
                tcg_gen_mov_tl(reg_last_res_Z, regAC);
                tcg_gen_mov_tl(reg_last_res_V, regAC);      // Save result (V flag)
            }
            tcg_gen_br(lbl_cont);

            gen_set_label(lbl_decimal);
            {
                // Code for "BCD" mode
                tcg_gen_mov_tl(tmp2, reg_last_res_CN);    // Save the old Carry value

                // There follows the code to compute the flags, which is just like in binary mode...
                tcg_gen_mov_tl(reg_last_op1_V, regAC);      // Save operand 1 (V flag)
                tcg_gen_mov_tl(reg_last_op2_V, regTMP);     // Save operand 2 (V flag)
                tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);     // Get the carry
                tcg_gen_add_tl(reg_last_res_CN, regAC, reg_last_res_CN);  // Add the carry
                tcg_gen_add_tl(reg_last_res_CN, reg_last_res_CN, regTMP); // Add the value
                tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_CN);   // Truncate to 8 bits
                tcg_gen_mov_tl(reg_last_res_V, reg_last_res_Z);      // Save result (V flag)

                // Now compute the result
                tcg_gen_xori_tl(regTMP, regTMP, 0x00FF);        // Get the real value back again...
                TCGv lo = tcg_temp_local_new();
                TCGv hi = tcg_temp_local_new();
                int no_adjust_lo = gen_new_label();
                int no_adjust_hi = gen_new_label();

                // Low nibble
                tcg_gen_andi_tl(lo, regAC, 0x0F);
                tcg_gen_shri_tl(tmp2, tmp2, 8);     // Get the carry
                tcg_gen_add_tl(lo, lo, tmp2);
                tcg_gen_andi_tl(tmp2, regTMP, 0x0F);    // We don't need the carry value anymore, so let's reuse the register.
                tcg_gen_addi_tl(tmp2, tmp2, 1);
                tcg_gen_sub_tl(lo, lo, tmp2);

                // High nibble
                tcg_gen_andi_tl(hi, regAC, 0xF0);
                tcg_gen_andi_tl(tmp2, regTMP, 0xF0);
                tcg_gen_sub_tl(hi, hi, tmp2);

                // See if we need to adjust the low nibble
                tcg_gen_brcondi_tl(TCG_COND_GE, lo, 0, no_adjust_lo);
                tcg_gen_subi_tl(lo, lo, 6);
                tcg_gen_subi_tl(hi, hi, 16);
                gen_set_label(no_adjust_lo);

                // See if we need to adjust the high nibble
                tcg_gen_brcondi_tl(TCG_COND_GE, hi, 0, no_adjust_hi);
                tcg_gen_subi_tl(hi, hi, 0x60);
                gen_set_label(no_adjust_hi);

                // Compute final result
                tcg_gen_andi_tl(regAC, lo, 0x0F);
                tcg_gen_or_tl(regAC, regAC, hi);
                tcg_gen_ext8u_tl(regAC, regAC);

                tcg_temp_free(hi);
                tcg_temp_free(lo);
            }

            gen_set_label(lbl_cont);
            tcg_temp_free(tmp2);
            return NO_EXIT;
        }


        /*
         *  Jumps
         */
        case iJMP_abs:  tcg_gen_movi_tl(regPC, getw_from_code(paddr));  return EXIT_PC_UPDATED;
        case iJMP_ind: {
            // NOTE: When address location is xxFF, the address will be read from xxFF and xx00 not from xxFF xx00+0100
            uint32_t jmp_address = getw_from_code(paddr);
            tcg_gen_movi_tl(regTMP, jmp_address);
            if((jmp_address & 0xFF) != 0xFF) {  // Easy case
                tcg_gen_qemu_ld16u(regPC, regTMP, 0);
            } else {    // Page boundary, complex case
                tcg_gen_qemu_ld8u(regPC, regTMP, 0);        // Put first byte in regPC, regPC = [jmp_address] & 0xFF
                uint32_t second_byte_location = (jmp_address & 0xFF00) | ((jmp_address + 1) & 0x00FF);
                tcg_gen_movi_tl(regTMP, second_byte_location);
                tcg_gen_qemu_ld8u(regTMP, regTMP, 0);       // Put second byte in regTMP
                tcg_gen_shli_tl(regTMP, regTMP, 8);
                tcg_gen_or_tl(regPC, regTMP, regPC);        // Join both
            }
            return EXIT_PC_UPDATED;
        }


        /*
         *  Branches
         */
        int cond;
        int mask;
        TCGv last_res;
        case iBEQ:  cond = TCG_COND_NE;     mask = 0x00FF;    last_res = reg_last_res_Z;     goto br_gen;
        case iBNE:  cond = TCG_COND_EQ;     mask = 0x00FF;    last_res = reg_last_res_Z;     goto br_gen;
        case iBPL:  cond = TCG_COND_NE;     mask = 0x0080;    last_res = reg_last_res_CN;    goto br_gen;
        case iBMI:  cond = TCG_COND_EQ;     mask = 0x0080;    last_res = reg_last_res_CN;    goto br_gen;
        case iBCC:  cond = TCG_COND_NE;     mask = 0x0100;    last_res = reg_last_res_CN;    goto br_gen;
        case iBCS:  cond = TCG_COND_EQ;     mask = 0x0100;    last_res = reg_last_res_CN;    goto br_gen;
        case iBVC:  cond = TCG_COND_NE;     mask = 0x80;   gen_V_flag(regTMP);  last_res = regTMP;  goto br_gen;
        case iBVS:  cond = TCG_COND_EQ;     mask = 0x80;   gen_V_flag(regTMP);  last_res = regTMP;  goto br_gen;

        br_gen: {
            // NOTE: the number taken from operand must be signed,
            //       because we can subtract from the PC...
            int8_t br_target = get_from_code(paddr);
            int lbl_nobranch = gen_new_label();
            tcg_gen_andi_tl(regTMP, last_res, mask);
            tcg_gen_brcondi_tl(cond, regTMP, 0, lbl_nobranch);
            tcg_gen_movi_tl(regPC, (*paddr + br_target) & 0xFFFF);
            tcg_gen_exit_tb(0);

            gen_set_label(lbl_nobranch);
            tcg_gen_movi_tl(regPC, *paddr);
            tcg_gen_exit_tb(0);
            return EXIT_PC_UPDATED;
        }


        /*
         * Calls and rets
         */
        case iJSR:  {
            gen_PPC(*paddr+1);
            tcg_gen_movi_tl(regPC, getw_from_code(paddr));
            return EXIT_PC_UPDATED;
        }
        case iRTS:  gen_iRTS(1);                     return EXIT_PC_UPDATED;
        case iBRK:  {
            gen_PPC(*paddr+1);
            gen_iPHP();
            tcg_gen_ori_tl(regSR, regSR,  flagI);      // Disable interrupts
            tcg_gen_movi_tl(regTMP, BRK_VEC);
            tcg_gen_qemu_ld16u(regPC, regTMP, 0);
            return EXIT_PC_UPDATED;
        }
        case iRTI:  gen_iPLP();     gen_iRTS(0);     return EXIT_PC_UPDATED;

        /*
         * Flags direct manipulations
         */

        case iSEC:  tcg_gen_ori_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);     return NO_EXIT;
        case iCLC:  tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x00FF);    return NO_EXIT;
        case iCLV: {
            // Optimization: bacause V = ~(OP1 ^ OP2) & (OP1 ^ RES) & 0x80, this guarantees that V = 0
            tcg_gen_mov_tl(reg_last_op2_V, reg_last_res_V);
            return NO_EXIT;
        }

        // Clear's and Set's  for D and I flags
        case iCLD:  tcg_gen_andi_tl(regSR, regSR, ~flagD);    return NO_EXIT;
        case iSED:  tcg_gen_ori_tl (regSR, regSR,  flagD);    return NO_EXIT;
        case iCLI:  tcg_gen_andi_tl(regSR, regSR, ~flagI);    return NO_EXIT;
        case iSEI:  tcg_gen_ori_tl (regSR, regSR,  flagI);    return NO_EXIT;


        /*
         *  Increment and Decrement
         */

        int8_t value;
        case iINX:  used_reg = regX;    value = +1;      goto inc_dec_gen;
        case iINY:  used_reg = regY;    value = +1;      goto inc_dec_gen;
        case iDEX:  used_reg = regX;    value = -1;      goto inc_dec_gen;
        case iDEY:  used_reg = regY;    value = -1;      goto inc_dec_gen;

        inc_dec_gen: {
            tcg_gen_addi_tl(used_reg, used_reg, value);
            tcg_gen_ext8u_tl(used_reg, used_reg);
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, used_reg);
            tcg_gen_mov_tl(reg_last_res_Z, used_reg);                     // Save result for Z flag computation
            return NO_EXIT;
        }

        case iINC_abs:      addr_func = gen_abs_mode_addr;          value = +1;     goto inc_dec_mem_gen;
        case iDEC_abs:      addr_func = gen_abs_mode_addr;          value = -1;     goto inc_dec_mem_gen;
        case iINC_zpg:      addr_func = gen_zero_page_mode_addr;    value = +1;     goto inc_dec_mem_gen;
        case iDEC_zpg:      addr_func = gen_zero_page_mode_addr;    value = -1;     goto inc_dec_mem_gen;
        case iINC_zpgX:     addr_func = gen_zero_page_X_mode_addr;  value = +1;     goto inc_dec_mem_gen;
        case iDEC_zpgX:     addr_func = gen_zero_page_X_mode_addr;  value = -1;     goto inc_dec_mem_gen;
        case iINC_absX:     addr_func = gen_Xabs_mode_addr;         value = +1;     goto inc_dec_mem_gen;
        case iDEC_absX:     addr_func = gen_Xabs_mode_addr;         value = -1;     goto inc_dec_mem_gen;

        inc_dec_mem_gen: {
            TCGv reg_value = tcg_temp_new();
            *paddr = (*addr_func)(regTMP, *paddr);      // regTMP has the address
            tcg_gen_qemu_ld8u(reg_value, regTMP, 0);
            tcg_gen_addi_tl(reg_value, reg_value, value);   // Do the computation
            tcg_gen_ext8u_tl(reg_value, reg_value);
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, reg_value);
            tcg_gen_mov_tl(reg_last_res_Z, reg_value);                    // Save result for Z flag computation
            tcg_gen_qemu_st8(reg_value, regTMP, 0);     // Store back the value
            tcg_temp_free(reg_value);
            return NO_EXIT;
        }

        /*
         * Shifts and rotates
         */

        case iASL_A: {
            tcg_gen_shli_tl(reg_last_res_CN, regAC, 1);    // Save result for N and C flag computation
            tcg_gen_ext8u_tl(regAC, reg_last_res_CN);      // Truncate to 8 bits
            tcg_gen_mov_tl(reg_last_res_Z, regAC);         // Save result for Z flag computation
            return NO_EXIT;
        }

        case iASL_zpg:      addr_func = gen_zero_page_mode_addr;    goto asl_mem_gen;
        case iASL_zpgX:     addr_func = gen_zero_page_X_mode_addr;  goto asl_mem_gen;
        case iASL_abs:      addr_func = gen_abs_mode_addr;          goto asl_mem_gen;
        case iASL_absX:     addr_func = gen_Xabs_mode_addr;         goto asl_mem_gen;

        asl_mem_gen: {
            *paddr = (*addr_func)(regTMP, *paddr);                // regTMP has the address
            tcg_gen_qemu_ld8u(reg_last_res_CN, regTMP, 0);
            tcg_gen_shli_tl(reg_last_res_CN, reg_last_res_CN, 1); // Save result for N and C flag computation
            tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_CN);    // Save result for Z flag computation
            tcg_gen_qemu_st8(reg_last_res_CN, regTMP, 0);         // Store back the value
            return NO_EXIT;
        }


        case iLSR_A: {
            tcg_gen_andi_tl(reg_last_res_CN, regAC, 0x01);            // Save first bit to carry
            tcg_gen_shli_tl(reg_last_res_CN, reg_last_res_CN, 8);
            tcg_gen_shri_tl(regAC, regAC, 1);                         // Shift it
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regAC);   // Save result for N and C flag computation
            tcg_gen_mov_tl(reg_last_res_Z, regAC);                    // Save result for Z flag computation
            return NO_EXIT;
        }

        case iLSR_zpg:      addr_func = gen_zero_page_mode_addr;    goto lsr_mem_gen;
        case iLSR_zpgX:     addr_func = gen_zero_page_X_mode_addr;  goto lsr_mem_gen;
        case iLSR_abs:      addr_func = gen_abs_mode_addr;          goto lsr_mem_gen;
        case iLSR_absX:     addr_func = gen_Xabs_mode_addr;         goto lsr_mem_gen;

        lsr_mem_gen: {
            TCGv reg_value = tcg_temp_new();
            *paddr = (*addr_func)(regTMP, *paddr);                       // regTMP has the address
            tcg_gen_qemu_ld8u(reg_value, regTMP, 0);
            tcg_gen_andi_tl(reg_last_res_CN, reg_value, 0x01);           // Save first bit to carry
            tcg_gen_shli_tl(reg_last_res_CN, reg_last_res_CN, 8);
            tcg_gen_shri_tl(reg_value, reg_value, 1);                    // Shift it
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, reg_value);  // Save result for N and C flag computation
            tcg_gen_mov_tl(reg_last_res_Z, reg_value);                   // Save result for Z flag computation
            tcg_gen_qemu_st8(reg_value, regTMP, 0);                      // Store back the value
            tcg_temp_free(reg_value);
            return NO_EXIT;
        }


        case iROL_A: {
            tcg_gen_shli_tl(regAC, regAC, 1);
            tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regAC);   // Save result for N and C flag computation
            tcg_gen_ext8u_tl(regAC, reg_last_res_CN);         // Truncate to 8 bits
            tcg_gen_mov_tl(reg_last_res_Z, regAC);            // Save result for Z flag computation
            return NO_EXIT;
        }
        case iROL_zpg:      addr_func = gen_zero_page_mode_addr;    goto rol_mem_gen;
        case iROL_zpgX:     addr_func = gen_zero_page_X_mode_addr;  goto rol_mem_gen;
        case iROL_abs:      addr_func = gen_abs_mode_addr;          goto rol_mem_gen;
        case iROL_absX:     addr_func = gen_Xabs_mode_addr;         goto rol_mem_gen;
        rol_mem_gen: {
            TCGv reg_value = tcg_temp_new();
            *paddr = (*addr_func)(regTMP, *paddr);                        // regTMP has the address
            tcg_gen_qemu_ld8u(reg_value, regTMP, 0);
            tcg_gen_shli_tl(reg_value, reg_value, 1);
            tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 8);
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, reg_value);   // Save result for N and C flag computation
            tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_CN);            // Save result for Z flag computation
            tcg_gen_qemu_st8(reg_last_res_CN, regTMP, 0);                 // Store back the value
            tcg_temp_free(reg_value);
            return NO_EXIT;
        }




        case iROR_A: {
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save previous carry
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regAC);       // Save result for N and C flag computation
            tcg_gen_andi_tl(regAC, regAC, 0x01);                          // Save first bit in AC
            tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 1);         // Shift it
            tcg_gen_shli_tl(regAC, regAC, 8);                             // Put saved bit in carry position
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regAC);       // Save new carry
            tcg_gen_ext8u_tl(regAC, reg_last_res_CN);                     // Truncate to 8 bits
            tcg_gen_mov_tl(reg_last_res_Z, regAC);                        // Save result for Z flag computation
            return NO_EXIT;
        }
        case iROR_zpg:      addr_func = gen_zero_page_mode_addr;    goto ror_mem_gen;
        case iROR_zpgX:     addr_func = gen_zero_page_X_mode_addr;  goto ror_mem_gen;
        case iROR_abs:      addr_func = gen_abs_mode_addr;          goto ror_mem_gen;
        case iROR_absX:     addr_func = gen_Xabs_mode_addr;         goto ror_mem_gen;
        ror_mem_gen: {
            TCGv reg_value = tcg_temp_new();
            *paddr = (*addr_func)(regTMP, *paddr);                        // regTMP has the address
            tcg_gen_qemu_ld8u(reg_value, regTMP, 0);
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save previous carry
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, reg_value);   // Save result for N and C flag computation
            tcg_gen_andi_tl(reg_value, reg_value, 0x01);                  // Save first bit in reg_value
            tcg_gen_shri_tl(reg_last_res_CN, reg_last_res_CN, 1);         // Shift it
            tcg_gen_shli_tl(reg_value, reg_value, 8);                     // Put saved bit in carry position
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, reg_value);   // Save new carry
            tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_CN);            // Save result for Z flag computation
            tcg_gen_qemu_st8(reg_last_res_CN, regTMP, 0);                 // Store back the value
            tcg_temp_free(reg_value);
            return NO_EXIT;
        }





        /*
         *  ANDs, ORs and XORs
         */
        void (*bitwise_func_imm)(TCGv,TCGv,int32_t);
        void (*bitwise_func)(TCGv,TCGv,TCGv);

        // Immediate
        case iAND_imm:  bitwise_func_imm = tcg_gen_andi_tl;     goto bitwise_gen_imm;
        case iORA_imm:  bitwise_func_imm = tcg_gen_ori_tl;      goto bitwise_gen_imm;
        case iEOR_imm:  bitwise_func_imm = tcg_gen_xori_tl;     goto bitwise_gen_imm;

        bitwise_gen_imm: {
            (*bitwise_func_imm)(regAC, regAC, get_from_code(paddr));
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regAC);
            tcg_gen_mov_tl(reg_last_res_Z, regAC);                         // Save result for Z flag computation
            return NO_EXIT;
        }

        // Other addressing modes
        case iAND_abs:  addr_func = gen_abs_mode;           bitwise_func = tcg_gen_and_tl;     goto bitwise_gen;
        case iORA_abs:  addr_func = gen_abs_mode;           bitwise_func = tcg_gen_or_tl;      goto bitwise_gen;
        case iEOR_abs:  addr_func = gen_abs_mode;           bitwise_func = tcg_gen_xor_tl;     goto bitwise_gen;

        case iAND_zpg:  addr_func = gen_zero_page_mode;     bitwise_func = tcg_gen_and_tl;     goto bitwise_gen;
        case iORA_zpg:  addr_func = gen_zero_page_mode;     bitwise_func = tcg_gen_or_tl;      goto bitwise_gen;
        case iEOR_zpg:  addr_func = gen_zero_page_mode;     bitwise_func = tcg_gen_xor_tl;     goto bitwise_gen;

        case iAND_Xind:  addr_func = gen_indirect_X_mode;   bitwise_func = tcg_gen_and_tl;     goto bitwise_gen;
        case iORA_Xind:  addr_func = gen_indirect_X_mode;   bitwise_func = tcg_gen_or_tl;      goto bitwise_gen;
        case iEOR_Xind:  addr_func = gen_indirect_X_mode;   bitwise_func = tcg_gen_xor_tl;     goto bitwise_gen;

        case iAND_indY:  addr_func = gen_Y_indirect_mode;   bitwise_func = tcg_gen_and_tl;     goto bitwise_gen;
        case iORA_indY:  addr_func = gen_Y_indirect_mode;   bitwise_func = tcg_gen_or_tl;      goto bitwise_gen;
        case iEOR_indY:  addr_func = gen_Y_indirect_mode;   bitwise_func = tcg_gen_xor_tl;     goto bitwise_gen;

        case iAND_zpgX:  addr_func = gen_zero_page_X_mode;  bitwise_func = tcg_gen_and_tl;     goto bitwise_gen;
        case iORA_zpgX:  addr_func = gen_zero_page_X_mode;  bitwise_func = tcg_gen_or_tl;      goto bitwise_gen;
        case iEOR_zpgX:  addr_func = gen_zero_page_X_mode;  bitwise_func = tcg_gen_xor_tl;     goto bitwise_gen;

        case iAND_absX:  addr_func = gen_Xabs_mode;         bitwise_func = tcg_gen_and_tl;     goto bitwise_gen;
        case iORA_absX:  addr_func = gen_Xabs_mode;         bitwise_func = tcg_gen_or_tl;      goto bitwise_gen;
        case iEOR_absX:  addr_func = gen_Xabs_mode;         bitwise_func = tcg_gen_xor_tl;     goto bitwise_gen;

        case iAND_absY:  addr_func = gen_Yabs_mode;         bitwise_func = tcg_gen_and_tl;     goto bitwise_gen;
        case iORA_absY:  addr_func = gen_Yabs_mode;         bitwise_func = tcg_gen_or_tl;      goto bitwise_gen;
        case iEOR_absY:  addr_func = gen_Yabs_mode;         bitwise_func = tcg_gen_xor_tl;     goto bitwise_gen;

        bitwise_gen: {
            *paddr = (*addr_func)(regTMP, *paddr);
            (*bitwise_func)(regAC, regAC, regTMP);
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regAC);
            tcg_gen_mov_tl(reg_last_res_Z, regAC);                        // Save result for Z flag computation
            return NO_EXIT;
        }


        /*
         * Compares and BIT
         */

        // Immediate
        case iCMP_imm:  used_reg = regAC;   goto cmp_gen_imm;
        case iCPX_imm:  used_reg = regX;    goto cmp_gen_imm;
        case iCPY_imm:  used_reg = regY;    goto cmp_gen_imm;

        cmp_gen_imm: {
            // Add ~M + 1 and save result for Z, N and C flag computation
            tcg_gen_addi_tl(reg_last_res_CN, used_reg, (get_from_code(paddr) ^ 0xFF) + 1);
            tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_CN);
            return NO_EXIT;
        }

        // Other addressing modes
        case iCMP_abs:   used_reg = regAC;    addr_func = gen_abs_mode;           goto cmp_gen;
        case iCPX_abs:   used_reg = regX;     addr_func = gen_abs_mode;           goto cmp_gen;
        case iCPY_abs:   used_reg = regY;     addr_func = gen_abs_mode;           goto cmp_gen;
        case iCMP_zpg:   used_reg = regAC;    addr_func = gen_zero_page_mode;     goto cmp_gen;
        case iCPX_zpg:   used_reg = regX;     addr_func = gen_zero_page_mode;     goto cmp_gen;
        case iCPY_zpg:   used_reg = regY;     addr_func = gen_zero_page_mode;     goto cmp_gen;
        case iCMP_Xind:  used_reg = regAC;    addr_func = gen_indirect_X_mode;    goto cmp_gen;
        case iCMP_indY:  used_reg = regAC;    addr_func = gen_Y_indirect_mode;    goto cmp_gen;
        case iCMP_zpgX:  used_reg = regAC;    addr_func = gen_zero_page_X_mode;   goto cmp_gen;
        case iCMP_absX:  used_reg = regAC;    addr_func = gen_Xabs_mode;          goto cmp_gen;
        case iCMP_absY:  used_reg = regAC;    addr_func = gen_Yabs_mode;          goto cmp_gen;

        cmp_gen: {
            *paddr = (*addr_func)(regTMP, *paddr);      // Get the value to add
            tcg_gen_sub_tl(reg_last_res_CN, used_reg, regTMP);     // Save result for N and C flag computation
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x01FF);    // Clear bits 31..9
            tcg_gen_xori_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Calculate carry
            tcg_gen_ext8u_tl(reg_last_res_Z, reg_last_res_CN);      // Save result for Z flag computation
            return NO_EXIT;
        }


        case iBIT_abs: addr_func = gen_abs_mode;           goto bit_gen;
        case iBIT_zpg: addr_func = gen_zero_page_mode;     goto bit_gen;

        bit_gen: {
            *paddr = (*addr_func)(regTMP, *paddr);      // Get the value to add
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Clear previous N flag value
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regTMP);      // Put new value in the N flag
            tcg_gen_and_tl(reg_last_res_Z, regAC, regTMP);                // Calculate Z flag
            tcg_gen_movi_tl(reg_last_op1_V, 0);                           // Calculate V flag
            tcg_gen_movi_tl(reg_last_op2_V, 0);
            tcg_gen_shli_tl(reg_last_res_V, regTMP, 1);
            return NO_EXIT;
        }



        /*
         * Stack opreations
         */
        case iPHA: {
            tcg_gen_ori_tl(regSP, regSP, 0x100);
            tcg_gen_qemu_st8(regAC, regSP, 0);
            tcg_gen_subi_tl(regSP, regSP, 0x100+1);
            tcg_gen_ext8u_tl(regSP, regSP);
            return NO_EXIT;
        }

        case iPLA: {
            tcg_gen_addi_tl(regSP, regSP, 1);
            tcg_gen_ori_tl(regSP, regSP, 0x100);    // By doing the sum this way we ensure the instruction respects bounds
            tcg_gen_qemu_ld8u(regAC, regSP, 0);
            tcg_gen_ext8u_tl(regSP, regSP);                         // No need to do bounds cheking again
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regAC);
            tcg_gen_mov_tl(reg_last_res_Z, regAC);              // Save result for Z flag computation
            return NO_EXIT;
        }

        case iPHP: {
            gen_iPHP();
            return NO_EXIT;
        }

        case iPLP: {
            gen_iPLP();
            return NO_EXIT;
        }

        case iNOP:  return NO_EXIT;



#ifdef DEBUG_6502
        // These are phony instructions to help debugging...
        // In a real 6502 these would be undocumented KIL instructions (they would stop the CPU)
        case 0x12:
            gen_helper_printnum(reg_last_res_Z);
            tcg_gen_movi_tl(regTMP, ' ');
            gen_helper_printchar(regTMP);
        case 0x32:
            gen_helper_printnum(reg_last_res_CN);
            tcg_gen_movi_tl(regTMP, ' ');
            gen_helper_printchar(regTMP);
            return NO_EXIT;
        case 0x52:  // Read number from stdin
            gen_helper_getnum(regAC);
            return NO_EXIT;
        case 0x72:  // Print number to stdout
            gen_helper_printnum(regAC);
            return NO_EXIT;
        case 0x92:  // Read char from stdin
            gen_helper_getchar(regAC);
            return NO_EXIT;
        case 0xB2:  // Write to stdout
            gen_helper_printchar(regAC);
            return NO_EXIT;
        case 0xD2:  // Shutdown VM
            gen_helper_shutdown();
            return EXIT_PC_STALE;
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
#else
        default: {
            // Ignore non-defined instructions.
            return NO_EXIT;
        }

        //
        //  Undocumented instructions
        //

        // Opcodes for KIL instruction, some collide with phony instructions, others don't
        case 0x12:  case 0x32:  case 0x52:  case 0x72:  case 0x92:  case 0xB2:  case 0xD2:
#endif
        case 0x02:  case 0x22:  case 0x42:  case 0x62:  case 0xF2:
            return EXIT_PC_UPDATED;     // Jump to current PC

        // NOP
        case 0x1A:  case 0x3A:  case 0x5A:  case 0x7A:  case 0xDA:  case 0xFA:
            return NO_EXIT;

        // DOPs and TOPs (double and triple NOPs)
        case 0x80:  case 0x82:  case 0x89:  case 0xC2:  case 0xE2:
            addr_func = NULL;   // Immediate
            goto nop_gen;

        case 0x04:  case 0x44:  case 0x64:
            addr_func = gen_zero_page_mode;
            goto nop_gen;

        case 0x14:  case 0x34:  case 0x54:  case 0x74:  case 0xD4:  case 0xF4:
            addr_func = gen_zero_page_X_mode;
            goto nop_gen;

        case 0x0C:
            addr_func = gen_abs_mode;
            goto nop_gen;

        case 0x1C:  case 0x3C:  case 0x5C:  case 0x7C:  case 0xDC:  case 0xFC:
            addr_func = gen_Xabs_mode;
            goto nop_gen;

        nop_gen: {
            if(addr_func == NULL) {
                get_from_code(paddr);
            } else {
                *paddr = (*addr_func)(regTMP, *paddr);
            }
            return NO_EXIT;
        }


        case iLAX_abs:   addr_func = gen_abs_mode;           goto lax_gen;
        case iLAX_absY:  addr_func = gen_Yabs_mode;          goto lax_gen;
        case iLAX_zpg:   addr_func = gen_zero_page_mode;     goto lax_gen;
        case iLAX_zpgY:  addr_func = gen_zero_page_Y_mode;   goto lax_gen;
        case iLAX_Xind:  addr_func = gen_indirect_X_mode;    goto lax_gen;
        case iLAX_indY:  addr_func = gen_Y_indirect_mode;    goto lax_gen;

        lax_gen: {
            *paddr = (*addr_func)(regAC, *paddr);
            tcg_gen_mov_tl(regX, regAC);
            tcg_gen_andi_tl(reg_last_res_CN, reg_last_res_CN, 0x0100);    // Save result for N flag computation
            tcg_gen_or_tl(reg_last_res_CN, reg_last_res_CN, regAC);
            tcg_gen_mov_tl(reg_last_res_Z, regAC);                        // Save result for Z flag computation
            return NO_EXIT;
        }


        case iSAX_abs:   addr_func = gen_abs_mode_addr;           goto sax_gen;
        case iSAX_zpg:   addr_func = gen_zero_page_mode_addr;     goto sax_gen;
        case iSAX_zpgY:  addr_func = gen_zero_page_Y_mode_addr;   goto sax_gen;
        case iSAX_Xind:  addr_func = gen_indirect_X_addr;         goto sax_gen;

        sax_gen: {
            *paddr = (*addr_func)(regTMP, *paddr);
            TCGv reg_value = tcg_temp_new();
            tcg_gen_and_tl(reg_value, regAC, regX);
            tcg_gen_qemu_st8(reg_value, regTMP, 0);
            tcg_temp_free(reg_value);
            return NO_EXIT;
        }


    }
}

static inline void gen_intermediate_code_internal(CPUState *env, TranslationBlock *tb, int search_pc)
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
        tcg_gen_movi_i32(regPC, ctx.pc);
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


CPU6502State *cpu_6502_init (const char *cpu_model)
{
    CPU6502State *env;

    env = g_malloc0(sizeof(CPU6502State));
    cpu_exec_init(env);
    cpu6502_translate_init();
    tlb_flush(env, 1);

    env->sr = (flagUNU | flagI);    // Unused flag is always 1, interrupts start disabled
    env->last_res_Z = 1;  // CPU must start with flag Z set to 0, so this can't be 0

    qemu_init_vcpu(env);
    return env;
}

void restore_state_to_opc(CPUState *env, TranslationBlock *tb, int pc_pos)
{
    env->pc = gen_opc_pc[pc_pos];
}
