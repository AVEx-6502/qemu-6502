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

target_phys_addr_t cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
    return addr;
}



void cpu_dump_state (CPUState *env, FILE *f, fprintf_function cpu_fprintf,
                     int flags)
{
    cpu_fprintf(f, "     AC  " TARGET_FMT_lx "\n",                              env->ac);
    cpu_fprintf(f, "      X  " TARGET_FMT_lx "       Y  " TARGET_FMT_lx "\n",   env->x, env->y);
    cpu_fprintf(f, "     SP  " TARGET_FMT_lx "      PC  " TARGET_FMT_lx "\n",   env->sp, env->pc);
    cpu_fprintf(f, "     SR  " TARGET_FMT_lx "\n",                              env->sr);
    cpu_fprintf(f, "\n");
/*
    cpu_fprintf(f, "     LAST_RES_CN  " TARGET_FMT_lx "      LAST_RES_Z  " TARGET_FMT_lx "\n",
                    env->last_res_CN, env->last_res_Z);
    cpu_fprintf(f, "     LAST_OP1_V   " TARGET_FMT_lx "      LAST_OP2_V  " TARGET_FMT_lx "\n",
                    env->last_op1_V, env->last_op2_V);
    cpu_fprintf(f, "     LAST_RES_V   " TARGET_FMT_lx "\n", env->last_res_V);
    cpu_fprintf(f, "\n");
*/
}
