/*
 *  6502 emulation cpu helpers for qemu.
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


#if defined(CONFIG_USER_ONLY)
int cpu_6502_handle_mmu_fault (CPUState *env, target_ulong address, int rw,
                                int mmu_idx)
{
    env->exception_index = EXCP_MMFAULT;
    env->trap_arg0 = address;
    return 1;
}

#else

target_phys_addr_t cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
    return addr & TARGET_PAGE_MASK;
}

int cpu_6502_handle_mmu_fault(CPUState *env, target_ulong addr, int rw,
                               int mmu_idx)
{
    tlb_set_page(env, addr & TARGET_PAGE_MASK, addr & TARGET_PAGE_MASK,
                 PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx, TARGET_PAGE_SIZE);
    return 0;
}
#endif /* USER_ONLY */

void do_interrupt (CPUState *env)
{
    fprintf(stderr, "Interrupt happened!\n");
}

void cpu_dump_state (CPUState *env, FILE *f, fprintf_function cpu_fprintf,
                     int flags)
{
    cpu_fprintf(f, "     PC  " TARGET_FMT_lx "      PS  %02x\n",
                env->pc, env->ps);

    cpu_fprintf(f, "     AC  " TARGET_FMT_lx "      X   " TARGET_FMT_lx "\n",
                env->ac, env->x);

    cpu_fprintf(f, "     Y   " TARGET_FMT_lx "      SR  " TARGET_FMT_lx "\n",
                env->y, env->sr);

    cpu_fprintf(f, "     SP  " TARGET_FMT_lx "\n", env->sp);

    cpu_fprintf(f, "\n");


    cpu_fprintf(f, "     LAST_RES_CN  " TARGET_FMT_lx "      LAST_RES_Z  " TARGET_FMT_lx "\n",
                    env->last_res_CN, env->last_res_Z);

    cpu_fprintf(f, "     LAST_OP1_V   " TARGET_FMT_lx "      LAST_OP2_V  " TARGET_FMT_lx "\n",
                    env->last_op1_V, env->last_op2_V);

    cpu_fprintf(f, "     LAST_RES_V   " TARGET_FMT_lx "\n", env->last_res_V);

    cpu_fprintf(f, "\n");
}
