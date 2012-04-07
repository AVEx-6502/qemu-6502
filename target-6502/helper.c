/*
 *  Alpha emulation cpu helpers for qemu.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "cpu.h"
#include "softfloat.h"

uint64_t cpu_alpha_load_fpcr (CPUState *env)
{
    uint64_t r = 0;
    uint8_t t;

    t = env->fpcr_exc_status;
    if (t) {
        r = FPCR_SUM;
        if (t & float_flag_invalid) {
            r |= FPCR_INV;
        }
        if (t & float_flag_divbyzero) {
            r |= FPCR_DZE;
        }
        if (t & float_flag_overflow) {
            r |= FPCR_OVF;
        }
        if (t & float_flag_underflow) {
            r |= FPCR_UNF;
        }
        if (t & float_flag_inexact) {
            r |= FPCR_INE;
        }
    }

    t = env->fpcr_exc_mask;
    if (t & float_flag_invalid) {
        r |= FPCR_INVD;
    }
    if (t & float_flag_divbyzero) {
        r |= FPCR_DZED;
    }
    if (t & float_flag_overflow) {
        r |= FPCR_OVFD;
    }
    if (t & float_flag_underflow) {
        r |= FPCR_UNFD;
    }
    if (t & float_flag_inexact) {
        r |= FPCR_INED;
    }

    switch (env->fpcr_dyn_round) {
    case float_round_nearest_even:
        r |= FPCR_DYN_NORMAL;
        break;
    case float_round_down:
        r |= FPCR_DYN_MINUS;
        break;
    case float_round_up:
        r |= FPCR_DYN_PLUS;
        break;
    case float_round_to_zero:
        r |= FPCR_DYN_CHOPPED;
        break;
    }

    if (env->fpcr_dnz) {
        r |= FPCR_DNZ;
    }
    if (env->fpcr_dnod) {
        r |= FPCR_DNOD;
    }
    if (env->fpcr_undz) {
        r |= FPCR_UNDZ;
    }

    return r;
}

void cpu_alpha_store_fpcr (CPUState *env, uint64_t val)
{
    uint8_t t;

    t = 0;
    if (val & FPCR_INV) {
        t |= float_flag_invalid;
    }
    if (val & FPCR_DZE) {
        t |= float_flag_divbyzero;
    }
    if (val & FPCR_OVF) {
        t |= float_flag_overflow;
    }
    if (val & FPCR_UNF) {
        t |= float_flag_underflow;
    }
    if (val & FPCR_INE) {
        t |= float_flag_inexact;
    }
    env->fpcr_exc_status = t;

    t = 0;
    if (val & FPCR_INVD) {
        t |= float_flag_invalid;
    }
    if (val & FPCR_DZED) {
        t |= float_flag_divbyzero;
    }
    if (val & FPCR_OVFD) {
        t |= float_flag_overflow;
    }
    if (val & FPCR_UNFD) {
        t |= float_flag_underflow;
    }
    if (val & FPCR_INED) {
        t |= float_flag_inexact;
    }
    env->fpcr_exc_mask = t;

    switch (val & FPCR_DYN_MASK) {
    case FPCR_DYN_CHOPPED:
        t = float_round_to_zero;
        break;
    case FPCR_DYN_MINUS:
        t = float_round_down;
        break;
    case FPCR_DYN_NORMAL:
        t = float_round_nearest_even;
        break;
    case FPCR_DYN_PLUS:
        t = float_round_up;
        break;
    }
    env->fpcr_dyn_round = t;

    env->fpcr_flush_to_zero
      = (val & (FPCR_UNDZ|FPCR_UNFD)) == (FPCR_UNDZ|FPCR_UNFD);

    env->fpcr_dnz = (val & FPCR_DNZ) != 0;
    env->fpcr_dnod = (val & FPCR_DNOD) != 0;
    env->fpcr_undz = (val & FPCR_UNDZ) != 0;
}

#if defined(CONFIG_USER_ONLY)
int cpu_alpha_handle_mmu_fault (CPUState *env, target_ulong address, int rw,
                                int mmu_idx)
{
    env->exception_index = EXCP_MMFAULT;
    env->trap_arg0 = address;
    return 1;
}
#else
void swap_shadow_regs(CPUState *env)
{
#if 0
    uint64_t i0, i1, i2, i3, i4, i5, i6, i7;

    i0 = env->ir[8];
    i1 = env->ir[9];
    i2 = env->ir[10];
    i3 = env->ir[11];
    i4 = env->ir[12];
    i5 = env->ir[13];
    i6 = env->ir[14];
    i7 = env->ir[25];

    env->ir[8]  = env->shadow[0];
    env->ir[9]  = env->shadow[1];
    env->ir[10] = env->shadow[2];
    env->ir[11] = env->shadow[3];
    env->ir[12] = env->shadow[4];
    env->ir[13] = env->shadow[5];
    env->ir[14] = env->shadow[6];
    env->ir[25] = env->shadow[7];

    env->shadow[0] = i0;
    env->shadow[1] = i1;
    env->shadow[2] = i2;
    env->shadow[3] = i3;
    env->shadow[4] = i4;
    env->shadow[5] = i5;
    env->shadow[6] = i6;
    env->shadow[7] = i7;
#endif
}





target_phys_addr_t cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
    return addr & TARGET_PAGE_MASK;
}

int cpu_alpha_handle_mmu_fault(CPUState *env, target_ulong addr, int rw,
                               int mmu_idx)
{
    tlb_set_page(env, addr & TARGET_PAGE_MASK, addr & TARGET_PAGE_MASK,
                 PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx, TARGET_PAGE_SIZE);
    return 0;
}
#endif /* USER_ONLY */

void do_interrupt (CPUState *env)
{
    int i = env->exception_index;

    if (qemu_loglevel_mask(CPU_LOG_INT)) {
        static int count;
        const char *name = "<unknown>";

        switch (i) {
        case EXCP_RESET:
            name = "reset";
            break;
        case EXCP_MCHK:
            name = "mchk";
            break;
        case EXCP_SMP_INTERRUPT:
            name = "smp_interrupt";
            break;
        case EXCP_CLK_INTERRUPT:
            name = "clk_interrupt";
            break;
        case EXCP_DEV_INTERRUPT:
            name = "dev_interrupt";
            break;
        case EXCP_MMFAULT:
            name = "mmfault";
            break;
        case EXCP_UNALIGN:
            name = "unalign";
            break;
        case EXCP_OPCDEC:
            name = "opcdec";
            break;
        case EXCP_ARITH:
            name = "arith";
            break;
        case EXCP_FEN:
            name = "fen";
            break;
        case EXCP_CALL_PAL:
            name = "call_pal";
            break;
        case EXCP_STL_C:
            name = "stl_c";
            break;
        case EXCP_STQ_C:
            name = "stq_c";
            break;
        }
        qemu_log("INT %6d: %s(%#x) pc=%016" PRIx32 " sp=%016" PRIx32 "\n",
                 ++count, name, env->error_code, env->pc, env->sp);
    }

    env->exception_index = -1;

#if !defined(CONFIG_USER_ONLY)
    switch (i) {
    case EXCP_RESET:
        i = 0x0000;
        break;
    case EXCP_MCHK:
        i = 0x0080;
        break;
    case EXCP_SMP_INTERRUPT:
        i = 0x0100;
        break;
    case EXCP_CLK_INTERRUPT:
        i = 0x0180;
        break;
    case EXCP_DEV_INTERRUPT:
        i = 0x0200;
        break;
    case EXCP_MMFAULT:
        i = 0x0280;
        break;
    case EXCP_UNALIGN:
        i = 0x0300;
        break;
    case EXCP_OPCDEC:
        i = 0x0380;
        break;
    case EXCP_ARITH:
        i = 0x0400;
        break;
    case EXCP_FEN:
        i = 0x0480;
        break;
    case EXCP_CALL_PAL:
        i = env->error_code;
        /* There are 64 entry points for both privileged and unprivileged,
           with bit 0x80 indicating unprivileged.  Each entry point gets
           64 bytes to do its job.  */
        if (i & 0x80) {
            i = 0x2000 + (i - 0x80) * 64;
        } else {
            i = 0x1000 + i * 64;
        }
        break;
    default:
        cpu_abort(env, "Unhandled CPU exception");
    }

    /* Remember where the exception happened.  Emulate real hardware in
       that the low bit of the PC indicates PALmode.  */
    env->exc_addr = env->pc | env->pal_mode;

    /* Continue execution at the PALcode entry point.  */
    env->pc = env->palbr + i;

    /* Switch to PALmode.  */
    if (!env->pal_mode) {
        env->pal_mode = 1;
        swap_shadow_regs(env);
    }
#endif /* !USER_ONLY */
}

void cpu_dump_state (CPUState *env, FILE *f, fprintf_function cpu_fprintf,
                     int flags)
{
    cpu_fprintf(f, "     PC  " TARGET_FMT_lx "      PS  %02x\n",
                env->pc, env->ps);

    cpu_fprintf(f, "     AC  " TARGET_FMT_lx "      X  " TARGET_FMT_lx "\n",
                env->ac, env->x);

    cpu_fprintf(f, "     Y  " TARGET_FMT_lx "      SR  " TARGET_FMT_lx "\n",
                env->y, env->sr);

    cpu_fprintf(f, "     SP  " TARGET_FMT_lx "\n", env->sp);

    cpu_fprintf(f, "lock_a   " TARGET_FMT_lx " lock_v   " TARGET_FMT_lx "\n",
                env->lock_addr, env->lock_value);

    cpu_fprintf(f, "\n");
}
