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







// Helpers for fake test instructions
#ifdef DEBUG_6502
void helper_printstuff (uint32_t addr, uint32_t instruction)
{
    fprintf(stderr, "\nNao implementado: addr=0x%"PRIX32", insn=0x%"PRIX32"!\n", addr, instruction);
    // Isto é querer sair do QEMU "à campeão", mas dá jeito para testar...
    fprintf(stderr, "Found unimplemented instruction. Shutting down . . .\n");
    fprintf(stdout, "\n"); fflush(stdout);
    exit(-1);
}

void helper_printchar (uint32_t ch)
{
    fprintf(stdout, "%c", (char)ch); fflush(stdout);
}

void helper_printnum (uint32_t num)
{
    fprintf(stdout, "%"PRIu32, num); fflush(stdout);
}

#include <termios.h>
#include <unistd.h>
#define fatal(ARG)  {fprintf(stderr, ARG); exit(-1);}
target_ulong helper_getchar (void)
{
    struct termios saved;
    if (tcgetattr(STDIN_FILENO, &saved) < 0) fatal("can't get tty settings");
    if (isatty(STDIN_FILENO)) {
        struct termios raw = saved;

        raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        raw.c_oflag &= ~(OPOST);
        raw.c_cflag |= (CS8);
        raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
        raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;

        if (tcsetattr(STDIN_FILENO,TCSANOW,&raw) < 0) fatal("can't set raw mode");
    }
    char ret;
    read(STDIN_FILENO, &ret, 1);
    if (isatty(STDIN_FILENO))
        if (tcsetattr(STDIN_FILENO,TCSANOW,&saved) < 0) fatal("can't restore old terminal mode");
    return ret;
}

target_ulong helper_getnum (void)
{
    unsigned ret;
    fscanf(stdin, "%u", &ret);
    return ret;
}

void helper_shutdown (void)
{
    fprintf(stdout, "\n"); fflush(stdout);
    exit(0);
}
#endif


/* Helper to call exceptions from generated code.
   We expect that ENV->PC has already been updated.  */

void QEMU_NORETURN helper_excp(int excp, int error)
{
    env->exception_index = excp;
    env->error_code = error;
    cpu_loop_exit(env);
}

/*****************************************************************************/
/*   Softmmu support                                                         */
#include "softmmu_exec.h"
#define MMUSUFFIX _mmu
#define SHIFT 0
#include "softmmu_template.h"
#define SHIFT 1
#include "softmmu_template.h"
#define SHIFT 2
#include "softmmu_template.h"
#define SHIFT 3
#include "softmmu_template.h"


void tlb_fill(CPUState *env1, target_ulong addr, int rw, int mmu_idx,
              void *retaddr)
{
    CPUState *saved_env = env;
    env = env1;
    // There's no need for stupid cpu_6502_handle_mmu_fault function, because the 6502 has no MMU, so...
    tlb_set_page(env, addr & TARGET_PAGE_MASK, addr & TARGET_PAGE_MASK,
                     PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx, TARGET_PAGE_SIZE);
    env = saved_env;
}





// Interrupt stuff

void do_interrupt (CPUState *env1)
{
    CPUState *saved_env;
    saved_env = env;
    env = env1;

    // Converting to unsigned to avoid rounding errors. Strictly
    //  speaking, as per the standard, int number are at least
    //  16 bits. In the 6502 adresses are 16-bits too.
    // NOTE: we are threating the index as the address at which
    //  the handler's adress will be peeked. This is not exactly
    //  like it would happen in a real proccessor.
    unsigned int interrupt_index = env1->exception_index;

    // Check if interrupts are on. This only matters for IRQs, other interrupts cannot be disabled
    if(interrupt_index != IRQ_VEC || (env1->sr & flagI) == 0) {

        fprintf(stderr, "Interrupt happened!\n");

        // Read the hendler's address
        unsigned int routine_addr = lduw_kernel(interrupt_index) & 0xFFFF;

        // Reset interrupt saves nothing, just jumps to new location
        if(interrupt_index != RESET_VEC) {
            // Put the return address in the stack
            stb_kernel((env1->sp + 0x100) & 0xFFFF, (env1->pc >> 8) & 0xFF);  // High word
            env1->sp = (env1->sp - 1) & 0xFF;
            stb_kernel((env1->sp + 0x100) & 0xFFFF, (env1->pc >> 0) & 0xFF);  // Low  word
            env1->sp = (env1->sp - 1) & 0xFF;
            // Put the flags in the stack
            stb_kernel((env1->sp + 0x100) & 0xFFFF, calc_6502_flags(env1, 0) & 0xFF);
            env1->sp = (env1->sp - 1) & 0xFF;
        }

        env1->sr |= flagI;
        env1->pc = routine_addr;
    }

    // We don't want the routine to be called again
    env1->exception_index = -1;
    env1->interrupt_request &= ~CPU_INTERRUPT_HARD;

    env = saved_env;

}

