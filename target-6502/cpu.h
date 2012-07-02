/*
 *  6502 emulation cpu definitions for qemu.
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

#if !defined (__CPU_6502_H__)
#define __CPU_6502_H__

#define DEBUG_6502

#include "config.h"
#include "qemu-common.h"

#define TARGET_LONG_BITS 32

// target supports implicit self modifying code
#define TARGET_HAS_SMC
// support for self modifying code even if the modified instruction is
//   close to the modifying instruction
#define TARGET_HAS_PRECISE_SMC

#define CPUState struct CPU6502State

#include "cpu-defs.h"
#include "softfloat.h"

#define TARGET_PAGE_BITS 7
#define TARGET_PHYS_ADDR_SPACE_BITS 32
#define TARGET_VIRT_ADDR_SPACE_BITS 32

/* MMU modes definitions */
#define NB_MMU_MODES 1
#define MMU_MODE0_SUFFIX _kernel
#define MMU_KERNEL_IDX   0

typedef struct CPU6502State CPU6502State;

struct CPU6502State {
    //      "General" Registers (they are really 8 bit, but as TCG doesn't
    // seem to have 8 bit registers, we are going to use more bits...
    uint32_t    ac;
    uint32_t    x;
    uint32_t    y;

    uint32_t    sp; // Stack pointer
    uint32_t    sr;     // These are the flags: NV-BDIZC
                        //  (note that only D,I are kept here; B is a ghost flag
                        //   that is generated only by events that put the flags
                        //   in the stack, and is only 1 for PHP)

    uint32_t    pc;

    uint32_t    tmp;
    uint32_t    last_res_CN;   // result of last operation, used to compute C and N flags
    uint32_t    last_res_Z;    // result of last operation, used to compute Z flag
    uint32_t    last_op1_V;    // last operands and result for V flag computation
    uint32_t    last_op2_V;
    uint32_t    last_res_V;


    /* Those resources are used only in Qemu core */
    CPU_COMMON

    int error_code;
};

#define CPU_INTERRUPT_IRQ       CPU_INTERRUPT_TGT_EXT_0
#define CPU_INTERRUPT_NMI       CPU_INTERRUPT_TGT_EXT_1
#define CPU_INTERRUPT_RESET     CPU_INTERRUPT_TGT_EXT_2

enum flag_masks {
    flagC   = (1<<0),
    flagZ   = (1<<1),
    flagI   = (1<<2),
    flagD   = (1<<3),
    flagB   = (1<<4),
    flagUNU = (1<<5),
    flagV   = (1<<6),
    flagN   = (1<<7),
};

#define cpu_init cpu_6502_init
#define cpu_exec cpu_6502_exec
#define cpu_gen_code cpu_6502_gen_code
#define cpu_signal_handler cpu_6502_signal_handler

#include "cpu-all.h"

static inline int cpu_mmu_index(CPUState *env)
{
    return MMU_KERNEL_IDX;
}

CPU6502State * cpu_6502_init (const char *cpu_model);
int cpu_6502_exec(CPU6502State *s);
/* you can call this signal handler from your SIGBUS and SIGSEGV
   signal handlers to inform the virtual CPU of exceptions. non zero
   is returned if the signal was handled by the virtual CPU.  */
int cpu_6502_signal_handler(int host_signum, void *pinfo, void *puc);
#define cpu_handle_mmu_fault cpu_6502_handle_mmu_fault
void do_interrupt (CPUState *env);

QEMU_NORETURN void cpu_unassigned_access(CPUState *env1,
                                         target_phys_addr_t addr, int is_write,
                                         int is_exec, int unused, int size);


static inline unsigned calc_6502_flags(CPUState *env, unsigned brk)
{
    unsigned c = ((env->last_res_CN&0xFF00) != 0);
    unsigned z = ((env->last_res_Z & 0xFF)== 0);
    //unsigned i;
    //unsigned d
    //unsigned b;
    //unsigned unu;
    unsigned v = (((env->last_op1_V ^ ~env->last_op2_V) & (env->last_op1_V ^ env->last_res_V) & 0x80) != 0);
    unsigned n = ((env->last_res_CN&0x80) != 0);

    return    c << 0
            | z << 1
            | (env->sr & (flagI|flagD))
            | (brk ? flagB : 0)
            | flagUNU
            | v << 6
            | n << 7;
}

static inline void cpu_get_tb_cpu_state(CPUState *env, target_ulong *pc,
                                        target_ulong *cs_base, int *pflags)
{
    *pc = env->pc;
    *cs_base = 0;

    *pflags = calc_6502_flags(env, 1);
}



static inline bool cpu_has_work(CPUState *env)
{
    return (env->interrupt_request & CPU_INTERRUPT_NMI)   ||
           (env->interrupt_request & CPU_INTERRUPT_RESET) ||
           ((env->interrupt_request & CPU_INTERRUPT_IRQ) && ((env->sr & flagI) == 0));
}

#include "exec-all.h"

static inline void cpu_pc_from_tb(CPUState *env, TranslationBlock *tb)
{
    env->pc = tb->pc;
}

#endif /* !defined (__CPU_6502_H__) */
