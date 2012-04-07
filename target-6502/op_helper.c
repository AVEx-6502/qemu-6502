/*
 *  6502 emulation cpu micro-operations helpers for qemu.
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
#include "dyngen-exec.h"
#include "host-utils.h"
#include "softfloat.h"
#include "helper.h"
#include "sysemu.h"
#include "qemu-timer.h"

#define FP_STATUS (env->fp_status)

/* This should only be called from translate, via gen_excp.
   We expect that ENV->PC has already been updated.  */
void QEMU_NORETURN helper_excp(int excp, int error)
{
    env->exception_index = excp;
    env->error_code = error;
    cpu_loop_exit(env);
}



static void do_restore_state(void *retaddr)
{
    unsigned long pc = (unsigned long)retaddr;

    if (pc) {
        TranslationBlock *tb = tb_find_pc(pc);
        if (tb) {
            cpu_restore_state(tb, env, pc);
        }
    }
}

/* This may be called from any of the helpers to set up EXCEPTION_INDEX.  */
static void QEMU_NORETURN dynamic_excp(int excp, int error)
{
    env->exception_index = excp;
    env->error_code = error;
    do_restore_state(GETPC());
    cpu_loop_exit(env);
}

static void QEMU_NORETURN arith_excp(int exc, uint64_t mask)
{
    env->trap_arg0 = exc;
    env->trap_arg1 = mask;
    dynamic_excp(EXCP_ARITH, 0);
}



void helper_printstuff (uint32_t addr, uint32_t instruction)
{
    fprintf(stderr, "\nNao implementado: addr=0x%"PRIX32", insn=0x%"PRIX32"!\n", addr, instruction);
    // Isto é querer sair do QEMU "à campeão", mas dá jeito para testar...
    fprintf(stderr, "Found unimplemented instruction. Shutting down . . .\n");
    fprintf(stdout, "\n"); fflush(stdout);
    exit(0);
}

void helper_printchar (uint32_t ch)
{
    fprintf(stdout, "%c", (char)ch); fflush(stdout);
}

target_ulong helper_getnum (void)
{
    unsigned ret;
    fscanf(stdin, "%*s");
    fscanf(stdin, "%u", &ret);
    return ret;
}






/*****************************************************************************/
/* Softmmu support */
#if !defined (CONFIG_USER_ONLY)
static void QEMU_NORETURN do_unaligned_access(target_ulong addr, int is_write,
                                              int is_user, void *retaddr)
{
    uint64_t pc;
    uint32_t insn;

    do_restore_state(retaddr);

    pc = env->pc;
    insn = ldl_code(pc);

    env->trap_arg0 = addr;
    env->trap_arg1 = insn >> 26;                /* opcode */
    env->trap_arg2 = (insn >> 21) & 31;         /* dest regno */
    helper_excp(EXCP_UNALIGN, 0);
}

void QEMU_NORETURN cpu_unassigned_access(CPUState *env1,
                                         target_phys_addr_t addr, int is_write,
                                         int is_exec, int unused, int size)
{
    env = env1;
    env->trap_arg0 = addr;
    env->trap_arg1 = is_write;
    dynamic_excp(EXCP_MCHK, 0);
}

#include "softmmu_exec.h"

#define MMUSUFFIX _mmu
#define ALIGNED_ONLY

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUState *env1, target_ulong addr, int is_write, int mmu_idx,
              void *retaddr)
{
    CPUState *saved_env;
    int ret;

    saved_env = env;
    env = env1;
    ret = cpu_6502_handle_mmu_fault(env, addr, is_write, mmu_idx);
    if (unlikely(ret != 0)) {
        do_restore_state(retaddr);
        /* Exception index and error code are already set */
        cpu_loop_exit(env);
    }
    env = saved_env;
}
#endif
