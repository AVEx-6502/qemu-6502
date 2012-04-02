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

/* global register indexes */
static TCGv_ptr cpu_env;
static TCGv cpu_ir[31];
static TCGv cpu_fir[31];
static TCGv cpu_pc;
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

static inline void gen_qemu_ldf(TCGv t0, TCGv t1, int flags)
{
    TCGv tmp = tcg_temp_new();
    TCGv_i32 tmp32 = tcg_temp_new_i32();
    tcg_gen_qemu_ld32u(tmp, t1, flags);
    tcg_gen_trunc_i64_i32(tmp32, tmp);
    gen_helper_memory_to_f(t0, tmp32);
    tcg_temp_free_i32(tmp32);
    tcg_temp_free(tmp);
}

static inline void gen_qemu_ldg(TCGv t0, TCGv t1, int flags)
{
    TCGv tmp = tcg_temp_new();
    tcg_gen_qemu_ld64(tmp, t1, flags);
    gen_helper_memory_to_g(t0, tmp);
    tcg_temp_free(tmp);
}

static inline void gen_qemu_lds(TCGv t0, TCGv t1, int flags)
{
    TCGv tmp = tcg_temp_new();
    TCGv_i32 tmp32 = tcg_temp_new_i32();
    tcg_gen_qemu_ld32u(tmp, t1, flags);
    tcg_gen_trunc_i64_i32(tmp32, tmp);
    gen_helper_memory_to_s(t0, tmp32);
    tcg_temp_free_i32(tmp32);
    tcg_temp_free(tmp);
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

static inline void gen_qemu_stf(TCGv t0, TCGv t1, int flags)
{
    TCGv_i32 tmp32 = tcg_temp_new_i32();
    TCGv tmp = tcg_temp_new();
    gen_helper_f_to_memory(tmp32, t0);
    tcg_gen_extu_i32_i64(tmp, tmp32);
    tcg_gen_qemu_st32(tmp, t1, flags);
    tcg_temp_free(tmp);
    tcg_temp_free_i32(tmp32);
}

static inline void gen_qemu_stg(TCGv t0, TCGv t1, int flags)
{
    TCGv tmp = tcg_temp_new();
    gen_helper_g_to_memory(tmp, t0);
    tcg_gen_qemu_st64(tmp, t1, flags);
    tcg_temp_free(tmp);
}

static inline void gen_qemu_sts(TCGv t0, TCGv t1, int flags)
{
    TCGv_i32 tmp32 = tcg_temp_new_i32();
    TCGv tmp = tcg_temp_new();
    gen_helper_s_to_memory(tmp32, t0);
    tcg_gen_extu_i32_i64(tmp, tmp32);
    tcg_gen_qemu_st32(tmp, t1, flags);
    tcg_temp_free(tmp);
    tcg_temp_free_i32(tmp32);
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

static void gen_qual_roundmode(DisasContext *ctx, int fn11)
{
    TCGv_i32 tmp;

    fn11 &= QUAL_RM_MASK;
    if (fn11 == ctx->tb_rm) {
        return;
    }
    ctx->tb_rm = fn11;

    tmp = tcg_temp_new_i32();
    switch (fn11) {
    case QUAL_RM_N:
        tcg_gen_movi_i32(tmp, float_round_nearest_even);
        break;
    case QUAL_RM_C:
        tcg_gen_movi_i32(tmp, float_round_to_zero);
        break;
    case QUAL_RM_M:
        tcg_gen_movi_i32(tmp, float_round_down);
        break;
    case QUAL_RM_D:
        tcg_gen_ld8u_i32(tmp, cpu_env, offsetof(CPUState, fpcr_dyn_round));
        break;
    }

#if defined(CONFIG_SOFTFLOAT_INLINE)
    /* ??? The "softfloat.h" interface is to call set_float_rounding_mode.
       With CONFIG_SOFTFLOAT that expands to an out-of-line call that just
       sets the one field.  */
    tcg_gen_st8_i32(tmp, cpu_env,
                    offsetof(CPUState, fp_status.float_rounding_mode));
#else
    gen_helper_setroundmode(tmp);
#endif

    tcg_temp_free_i32(tmp);
}

static void gen_qual_flushzero(DisasContext *ctx, int fn11)
{
    TCGv_i32 tmp;

    fn11 &= QUAL_U;
    if (fn11 == ctx->tb_ftz) {
        return;
    }
    ctx->tb_ftz = fn11;

    tmp = tcg_temp_new_i32();
    if (fn11) {
        /* Underflow is enabled, use the FPCR setting.  */
        tcg_gen_ld8u_i32(tmp, cpu_env, offsetof(CPUState, fpcr_flush_to_zero));
    } else {
        /* Underflow is disabled, force flush-to-zero.  */
        tcg_gen_movi_i32(tmp, 1);
    }

#if defined(CONFIG_SOFTFLOAT_INLINE)
    tcg_gen_st8_i32(tmp, cpu_env,
                    offsetof(CPUState, fp_status.flush_to_zero));
#else
    gen_helper_setflushzero(tmp);
#endif

    tcg_temp_free_i32(tmp);
}

static TCGv gen_ieee_input(int reg, int fn11, int is_cmp)
{
    TCGv val = tcg_temp_new();
    if (reg == 31) {
        tcg_gen_movi_i64(val, 0);
    } else if (fn11 & QUAL_S) {
        gen_helper_ieee_input_s(val, cpu_fir[reg]);
    } else if (is_cmp) {
        gen_helper_ieee_input_cmp(val, cpu_fir[reg]);
    } else {
        gen_helper_ieee_input(val, cpu_fir[reg]);
    }
    return val;
}

static void gen_fp_exc_clear(void)
{
#if defined(CONFIG_SOFTFLOAT_INLINE)
    TCGv_i32 zero = tcg_const_i32(0);
    tcg_gen_st8_i32(zero, cpu_env,
                    offsetof(CPUState, fp_status.float_exception_flags));
    tcg_temp_free_i32(zero);
#else
    gen_helper_fp_exc_clear();
#endif
}

static void gen_fp_exc_raise_ignore(int rc, int fn11, int ignore)
{
    /* ??? We ought to be able to do something with imprecise exceptions.
       E.g. notice we're still in the trap shadow of something within the
       TB and do not generate the code to signal the exception; end the TB
       when an exception is forced to arrive, either by consumption of a
       register value or TRAPB or EXCB.  */
    TCGv_i32 exc = tcg_temp_new_i32();
    TCGv_i32 reg;

#if defined(CONFIG_SOFTFLOAT_INLINE)
    tcg_gen_ld8u_i32(exc, cpu_env,
                     offsetof(CPUState, fp_status.float_exception_flags));
#else
    gen_helper_fp_exc_get(exc);
#endif

    if (ignore) {
        tcg_gen_andi_i32(exc, exc, ~ignore);
    }

    /* ??? Pass in the regno of the destination so that the helper can
       set EXC_MASK, which contains a bitmask of destination registers
       that have caused arithmetic traps.  A simple userspace emulation
       does not require this.  We do need it for a guest kernel's entArith,
       or if we were to do something clever with imprecise exceptions.  */
    reg = tcg_const_i32(rc + 32);

    if (fn11 & QUAL_S) {
        gen_helper_fp_exc_raise_s(exc, reg);
    } else {
        gen_helper_fp_exc_raise(exc, reg);
    }

    tcg_temp_free_i32(reg);
    tcg_temp_free_i32(exc);
}

static inline void gen_fp_exc_raise(int rc, int fn11)
{
    gen_fp_exc_raise_ignore(rc, fn11, fn11 & QUAL_I ? 0 : float_flag_inexact);
}


#define FARITH2(name)                                   \
static inline void glue(gen_f, name)(int rb, int rc)    \
{                                                       \
    if (unlikely(rc == 31)) {                           \
        return;                                         \
    }                                                   \
    if (rb != 31) {                                     \
        gen_helper_ ## name (cpu_fir[rc], cpu_fir[rb]); \
    } else {                                                \
        TCGv tmp = tcg_const_i64(0);                    \
        gen_helper_ ## name (cpu_fir[rc], tmp);         \
        tcg_temp_free(tmp);                             \
    }                                                   \
}

/* ??? VAX instruction qualifiers ignored.  */
FARITH2(sqrtf)
FARITH2(sqrtg)
FARITH2(cvtgf)
FARITH2(cvtgq)
FARITH2(cvtqf)
FARITH2(cvtqg)

static void gen_ieee_arith2(DisasContext *ctx, void (*helper)(TCGv, TCGv),
                            int rb, int rc, int fn11)
{
    TCGv vb;

    /* ??? This is wrong: the instruction is not a nop, it still may
       raise exceptions.  */
    if (unlikely(rc == 31)) {
        return;
    }

    gen_qual_roundmode(ctx, fn11);
    gen_qual_flushzero(ctx, fn11);
    gen_fp_exc_clear();

    vb = gen_ieee_input(rb, fn11, 0);
    helper(cpu_fir[rc], vb);
    tcg_temp_free(vb);

    gen_fp_exc_raise(rc, fn11);
}

#define IEEE_ARITH2(name)                                       \
static inline void glue(gen_f, name)(DisasContext *ctx,         \
                                     int rb, int rc, int fn11)  \
{                                                               \
    gen_ieee_arith2(ctx, gen_helper_##name, rb, rc, fn11);      \
}
IEEE_ARITH2(sqrts)
IEEE_ARITH2(sqrtt)
IEEE_ARITH2(cvtst)
IEEE_ARITH2(cvtts)


static void gen_ieee_intcvt(DisasContext *ctx, void (*helper)(TCGv, TCGv),
                            int rb, int rc, int fn11)
{
    TCGv vb;

    /* ??? This is wrong: the instruction is not a nop, it still may
       raise exceptions.  */
    if (unlikely(rc == 31)) {
        return;
    }

    gen_qual_roundmode(ctx, fn11);

    if (rb == 31) {
        vb = tcg_const_i64(0);
    } else {
        vb = cpu_fir[rb];
    }

    /* The only exception that can be raised by integer conversion
       is inexact.  Thus we only need to worry about exceptions when
       inexact handling is requested.  */
    if (fn11 & QUAL_I) {
        gen_fp_exc_clear();
        helper(cpu_fir[rc], vb);
        gen_fp_exc_raise(rc, fn11);
    } else {
        helper(cpu_fir[rc], vb);
    }

    if (rb == 31) {
        tcg_temp_free(vb);
    }
}

#define IEEE_INTCVT(name)                                       \
static inline void glue(gen_f, name)(DisasContext *ctx,         \
                                     int rb, int rc, int fn11)  \
{                                                               \
    gen_ieee_intcvt(ctx, gen_helper_##name, rb, rc, fn11);      \
}
IEEE_INTCVT(cvtqs)
IEEE_INTCVT(cvtqt)

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

#define FARITH3(name)                                           \
static inline void glue(gen_f, name)(int ra, int rb, int rc)    \
{                                                               \
    TCGv va, vb;                                                \
                                                                \
    if (unlikely(rc == 31)) {                                   \
        return;                                                 \
    }                                                           \
    if (ra == 31) {                                             \
        va = tcg_const_i64(0);                                  \
    } else {                                                    \
        va = cpu_fir[ra];                                       \
    }                                                           \
    if (rb == 31) {                                             \
        vb = tcg_const_i64(0);                                  \
    } else {                                                    \
        vb = cpu_fir[rb];                                       \
    }                                                           \
                                                                \
    gen_helper_ ## name (cpu_fir[rc], va, vb);                  \
                                                                \
    if (ra == 31) {                                             \
        tcg_temp_free(va);                                      \
    }                                                           \
    if (rb == 31) {                                             \
        tcg_temp_free(vb);                                      \
    }                                                           \
}

/* ??? VAX instruction qualifiers ignored.  */
FARITH3(addf)
FARITH3(subf)
FARITH3(mulf)
FARITH3(divf)
FARITH3(addg)
FARITH3(subg)
FARITH3(mulg)
FARITH3(divg)
FARITH3(cmpgeq)
FARITH3(cmpglt)
FARITH3(cmpgle)

static void gen_ieee_arith3(DisasContext *ctx,
                            void (*helper)(TCGv, TCGv, TCGv),
                            int ra, int rb, int rc, int fn11)
{
    TCGv va, vb;

    /* ??? This is wrong: the instruction is not a nop, it still may
       raise exceptions.  */
    if (unlikely(rc == 31)) {
        return;
    }

    gen_qual_roundmode(ctx, fn11);
    gen_qual_flushzero(ctx, fn11);
    gen_fp_exc_clear();

    va = gen_ieee_input(ra, fn11, 0);
    vb = gen_ieee_input(rb, fn11, 0);
    helper(cpu_fir[rc], va, vb);
    tcg_temp_free(va);
    tcg_temp_free(vb);

    gen_fp_exc_raise(rc, fn11);
}

#define IEEE_ARITH3(name)                                               \
static inline void glue(gen_f, name)(DisasContext *ctx,                 \
                                     int ra, int rb, int rc, int fn11)  \
{                                                                       \
    gen_ieee_arith3(ctx, gen_helper_##name, ra, rb, rc, fn11);          \
}
IEEE_ARITH3(adds)
IEEE_ARITH3(subs)
IEEE_ARITH3(muls)
IEEE_ARITH3(divs)
IEEE_ARITH3(addt)
IEEE_ARITH3(subt)
IEEE_ARITH3(mult)
IEEE_ARITH3(divt)

static void gen_ieee_compare(DisasContext *ctx,
                             void (*helper)(TCGv, TCGv, TCGv),
                             int ra, int rb, int rc, int fn11)
{
    TCGv va, vb;

    /* ??? This is wrong: the instruction is not a nop, it still may
       raise exceptions.  */
    if (unlikely(rc == 31)) {
        return;
    }

    gen_fp_exc_clear();

    va = gen_ieee_input(ra, fn11, 1);
    vb = gen_ieee_input(rb, fn11, 1);
    helper(cpu_fir[rc], va, vb);
    tcg_temp_free(va);
    tcg_temp_free(vb);

    gen_fp_exc_raise(rc, fn11);
}

#define IEEE_CMP3(name)                                                 \
static inline void glue(gen_f, name)(DisasContext *ctx,                 \
                                     int ra, int rb, int rc, int fn11)  \
{                                                                       \
    gen_ieee_compare(ctx, gen_helper_##name, ra, rb, rc, fn11);         \
}
IEEE_CMP3(cmptun)
IEEE_CMP3(cmpteq)
IEEE_CMP3(cmptlt)
IEEE_CMP3(cmptle)

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

/* Implement zapnot with an immediate operand, which expands to some
   form of immediate AND.  This is a basic building block in the
   definition of many of the other byte manipulation instructions.  */
static void gen_zapnoti(TCGv dest, TCGv src, uint8_t lit)
{
    switch (lit) {
    case 0x00:
        tcg_gen_movi_i64(dest, 0);
        break;
    case 0x01:
        tcg_gen_ext8u_i64(dest, src);
        break;
    case 0x03:
        tcg_gen_ext16u_i64(dest, src);
        break;
    case 0x0f:
        tcg_gen_ext32u_i64(dest, src);
        break;
    case 0xff:
        tcg_gen_mov_i64(dest, src);
        break;
    default:
        tcg_gen_andi_i64 (dest, src, zapnot_mask (lit));
        break;
    }
}

static inline void gen_zapnot(int ra, int rb, int rc, int islit, uint8_t lit)
{
    if (unlikely(rc == 31))
        return;
    else if (unlikely(ra == 31))
        tcg_gen_movi_i64(cpu_ir[rc], 0);
    else if (islit)
        gen_zapnoti(cpu_ir[rc], cpu_ir[ra], lit);
    else
        gen_helper_zapnot (cpu_ir[rc], cpu_ir[ra], cpu_ir[rb]);
}

static inline void gen_zap(int ra, int rb, int rc, int islit, uint8_t lit)
{
    if (unlikely(rc == 31))
        return;
    else if (unlikely(ra == 31))
        tcg_gen_movi_i64(cpu_ir[rc], 0);
    else if (islit)
        gen_zapnoti(cpu_ir[rc], cpu_ir[ra], ~lit);
    else
        gen_helper_zap (cpu_ir[rc], cpu_ir[ra], cpu_ir[rb]);
}




/* Code to call arith3 helpers */
#define ARITH3(name)                                                  \
static inline void glue(gen_, name)(int ra, int rb, int rc, int islit,\
                                    uint8_t lit)                      \
{                                                                     \
    if (unlikely(rc == 31))                                           \
        return;                                                       \
                                                                      \
    if (ra != 31) {                                                   \
        if (islit) {                                                  \
            TCGv tmp = tcg_const_i64(lit);                            \
            gen_helper_ ## name(cpu_ir[rc], cpu_ir[ra], tmp);         \
            tcg_temp_free(tmp);                                       \
        } else                                                        \
            gen_helper_ ## name (cpu_ir[rc], cpu_ir[ra], cpu_ir[rb]); \
    } else {                                                          \
        TCGv tmp1 = tcg_const_i64(0);                                 \
        if (islit) {                                                  \
            TCGv tmp2 = tcg_const_i64(lit);                           \
            gen_helper_ ## name (cpu_ir[rc], tmp1, tmp2);             \
            tcg_temp_free(tmp2);                                      \
        } else                                                        \
            gen_helper_ ## name (cpu_ir[rc], tmp1, cpu_ir[rb]);       \
        tcg_temp_free(tmp1);                                          \
    }                                                                 \
}
ARITH3(cmpbge)
ARITH3(addlv)
ARITH3(sublv)
ARITH3(addqv)
ARITH3(subqv)
ARITH3(umulh)
ARITH3(mullv)
ARITH3(mulqv)
ARITH3(minub8)
ARITH3(minsb8)
ARITH3(minuw4)
ARITH3(minsw4)
ARITH3(maxub8)
ARITH3(maxsb8)
ARITH3(maxuw4)
ARITH3(maxsw4)
ARITH3(perr)

#define MVIOP2(name)                                    \
static inline void glue(gen_, name)(int rb, int rc)     \
{                                                       \
    if (unlikely(rc == 31))                             \
        return;                                         \
    if (unlikely(rb == 31))                             \
        tcg_gen_movi_i64(cpu_ir[rc], 0);                \
    else                                                \
        gen_helper_ ## name (cpu_ir[rc], cpu_ir[rb]);   \
}
MVIOP2(pklb)
MVIOP2(pkwb)
MVIOP2(unpkbl)
MVIOP2(unpkbw)



static ExitStatus translate_one(DisasContext *ctx, uint32_t insn)
{
    {
        TCGv_i32 tmp = tcg_temp_new_i32();
        TCGv_i64 tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i32(tmp, insn);
        tcg_gen_movi_i64(tmp2, ctx->pc-4);
        gen_helper_printstuff(tmp2, tmp);
        tcg_temp_free_i64(tmp2);
        tcg_temp_free_i32(tmp);
    }

    if (insn == 0) {
        tcg_gen_movi_i64(cpu_pc, ctx->pc-4);
        return EXIT_PC_UPDATED;
    } else
        return NO_EXIT;
}

#if 0
// Load operand for "X,ind" addressing mode (looks like black magic but it's real!)...
// In the black lang of Mordor (6502 assembly syntax), it's written ($BB,X).
// In high elvish (x86 assembly syntax), this means [[X+[ 0x?? ]]].
static inline void gen_load_xind(unsigned zpg_imm)
{
    TGVv_i32 zpg = tcg_temp_new_i32();
    tcg_gen_movi_i32(zpg, zpg_imm);
    tcg_gen_qemu_ld8u(zpg_tmp, zpg, ????);
    tcg_gen_addi_i64(zpg_tmp, cpu_x);
    tcg_gen_qemu_ld16u(zpg_tmp, zpg_tmp, ????);
    tcg_gen_qemu_ld8u(op_this_instr, zpg_tmp, ????);
    tcg_temp_free_i32(zpg);
}
#endif


static inline void gen_intermediate_code_internal(CPUState *env,
                                                  TranslationBlock *tb,
                                                  int search_pc)
{
    DisasContext ctx, *ctxp = &ctx;
    target_ulong pc_start;
    uint32_t insn;
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
        insn = ldl_code(ctx.pc);
        num_insns++;

        if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP))) {
            tcg_gen_debug_insn_start(ctx.pc);
        }

        ctx.pc += 4;
        ret = translate_one(ctxp, insn);

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
