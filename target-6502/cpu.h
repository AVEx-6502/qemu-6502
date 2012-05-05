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





#include "config.h"
#include "qemu-common.h"

#define TARGET_LONG_BITS 32

#define CPUState struct CPU6502State

#include "cpu-defs.h"

#include "softfloat.h"

#define TARGET_HAS_ICE 1

#define ELF_MACHINE     EM_NONE

#define ICACHE_LINE_SIZE 32
#define DCACHE_LINE_SIZE 32


#define TARGET_PAGE_BITS 7
#define TARGET_PHYS_ADDR_SPACE_BITS 32
#define TARGET_VIRT_ADDR_SPACE_BITS 32


enum {
    AMASK_BWX      = 0x00000001,
    AMASK_FIX      = 0x00000002,
    AMASK_CIX      = 0x00000004,
    AMASK_MVI      = 0x00000100,
    AMASK_TRAP     = 0x00000200,
    AMASK_PREFETCH = 0x00001000,
};


/* MMU modes definitions */

/* Alpha has 5 MMU modes: PALcode, kernel, executive, supervisor, and user.
   The Unix PALcode only exposes the kernel and user modes; presumably
   executive and supervisor are used by VMS.

   PALcode itself uses physical mode for code and kernel mode for data;
   there are PALmode instructions that can access data via physical mode
   or via an os-installed "alternate mode", which is one of the 4 above.

   QEMU does not currently properly distinguish between code/data when
   looking up addresses.  To avoid having to address this issue, our
   emulated PALcode will cheat and use the KSEG mapping for its code+data
   rather than physical addresses.

   Moreover, we're only emulating Unix PALcode, and not attempting VMS.

   All of which allows us to drop all but kernel and user modes.
   Elide the unused MMU modes to save space.  */

#define NB_MMU_MODES 2

#define MMU_MODE0_SUFFIX _kernel
#define MMU_MODE1_SUFFIX _user
#define MMU_KERNEL_IDX   0
#define MMU_USER_IDX     1

typedef struct CPU6502State CPU6502State;

struct CPU6502State {
    //      "General" Registers (they are really 8 bit, but as TCG doesn't
    // seem to have 8 bit registers, we are going to use more bits...
    uint32_t    ac;
    uint32_t    x;
    uint32_t    y;

    uint32_t    sp;
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


    /* The Internal Processor Registers.  Some of these we assume always
       exist for use in user-mode.  */
    uint8_t ps;
    uint8_t fen;

    /* These pass data from the exception logic in the translator and
       helpers to the OS entry point.  This is used for both system
       emulation and user-mode.  */
    uint64_t trap_arg0;
    uint64_t trap_arg1;
    uint64_t trap_arg2;

    /* Those resources are used only in Qemu core */
    CPU_COMMON

    int error_code;

    uint32_t amask;
};

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

enum {
    FEATURE_ASN    = 0x00000001,
    FEATURE_SPS    = 0x00000002,
    FEATURE_VIRBND = 0x00000004,
    FEATURE_TBCHK  = 0x00000008,
};


enum {
    EXCP_RESET,
    EXCP_MCHK,
    EXCP_SMP_INTERRUPT,
    EXCP_CLK_INTERRUPT,
    EXCP_DEV_INTERRUPT,
    EXCP_MMFAULT,
    EXCP_UNALIGN,
    EXCP_OPCDEC,
    EXCP_ARITH,
    EXCP_FEN,
    EXCP_CALL_PAL,
    /* For Usermode emulation.  */
    EXCP_STL_C,
    EXCP_STQ_C,
};



/* Alpha-specific interrupt pending bits.  */
#define CPU_INTERRUPT_TIMER CPU_INTERRUPT_TGT_EXT_0
#define CPU_INTERRUPT_SMP   CPU_INTERRUPT_TGT_EXT_1
#define CPU_INTERRUPT_MCHK  CPU_INTERRUPT_TGT_EXT_2


/* Processor status constants.  */
enum {
    /* Low 3 bits are interrupt mask level.  */
    PS_INT_MASK = 7,

    /* Bits 4 and 5 are the mmu mode.  The VMS PALcode uses all 4 modes;
       The Unix PALcode only uses bit 4.  */
    PS_USER_MODE = 8
};

static inline int cpu_mmu_index(CPUState *env)
{
    if (env->ps & PS_USER_MODE) {
        return MMU_USER_IDX;
    } else {
        return MMU_KERNEL_IDX;
    }
}


CPU6502State * cpu_6502_init (const char *cpu_model);
int cpu_6502_exec(CPU6502State *s);
/* you can call this signal handler from your SIGBUS and SIGSEGV
   signal handlers to inform the virtual CPU of exceptions. non zero
   is returned if the signal was handled by the virtual CPU.  */
int cpu_6502_signal_handler(int host_signum, void *pinfo,
                             void *puc);
int cpu_6502_handle_mmu_fault (CPUState *env, uint32_t address, int rw,
                                int mmu_idx);
#define cpu_handle_mmu_fault cpu_6502_handle_mmu_fault
void do_interrupt (CPUState *env);

#ifndef CONFIG_USER_ONLY
QEMU_NORETURN void cpu_unassigned_access(CPUState *env1,
                                         target_phys_addr_t addr, int is_write,
                                         int is_exec, int unused, int size);
#endif

/* Bits in TB->FLAGS that control how translation is processed.  */
enum {
    TB_FLAGS_PAL_MODE = 1,
    TB_FLAGS_FEN = 2,
    TB_FLAGS_USER_MODE = 8,

    TB_FLAGS_AMASK_SHIFT = 4,
    TB_FLAGS_AMASK_BWX = AMASK_BWX << TB_FLAGS_AMASK_SHIFT,
    TB_FLAGS_AMASK_FIX = AMASK_FIX << TB_FLAGS_AMASK_SHIFT,
    TB_FLAGS_AMASK_CIX = AMASK_CIX << TB_FLAGS_AMASK_SHIFT,
    TB_FLAGS_AMASK_MVI = AMASK_MVI << TB_FLAGS_AMASK_SHIFT,
    TB_FLAGS_AMASK_TRAP = AMASK_TRAP << TB_FLAGS_AMASK_SHIFT,
    TB_FLAGS_AMASK_PREFETCH = AMASK_PREFETCH << TB_FLAGS_AMASK_SHIFT,
};

static inline void cpu_get_tb_cpu_state(CPUState *env, target_ulong *pc,
                                        target_ulong *cs_base, int *pflags)
{
    int flags = 0;

    *pc = env->pc;
    *cs_base = 0;

    flags = env->ps & PS_USER_MODE;

    if (env->fen) {
        flags |= TB_FLAGS_FEN;
    }
    flags |= env->amask << TB_FLAGS_AMASK_SHIFT;

    *pflags = flags;
}

#if defined(CONFIG_USER_ONLY)
static inline void cpu_clone_regs(CPUState *env, target_ulong newsp)
{
    if (newsp) {
        env->ir[IR_SP] = newsp;
    }
    env->ir[IR_V0] = 0;
    env->ir[IR_A3] = 0;
}

static inline void cpu_set_tls(CPUState *env, target_ulong newtls)
{
    env->unique = newtls;
}
#endif

static inline bool cpu_has_work(CPUState *env)
{
    /* Here we are checking to see if the CPU should wake up from HALT.
       We will have gotten into this state only for WTINT from PALmode.  */
    /* ??? I'm not sure how the IPL state works with WTINT to keep a CPU
       asleep even if (some) interrupts have been asserted.  For now,
       assume that if a CPU really wants to stay asleep, it will mask
       interrupts at the chipset level, which will prevent these bits
       from being set in the first place.  */
    return env->interrupt_request & (CPU_INTERRUPT_HARD
                                     | CPU_INTERRUPT_TIMER
                                     | CPU_INTERRUPT_SMP
                                     | CPU_INTERRUPT_MCHK);
}

#include "exec-all.h"

static inline void cpu_pc_from_tb(CPUState *env, TranslationBlock *tb)
{
    env->pc = tb->pc;
}

#endif /* !defined (__CPU_6502_H__) */
