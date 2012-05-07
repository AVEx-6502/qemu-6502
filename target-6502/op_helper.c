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
    //fscanf(stdin, "%*s");
    //fscanf(stdin, "%c", &ret);

    if (isatty(STDIN_FILENO)) {
        if (tcsetattr(STDIN_FILENO,TCSANOW,&saved) < 0) fatal("can't restore old terminal mode");
    }

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












#define FP_STATUS (env->fp_status)

/* This should only be called from translate, via gen_excp.
   We expect that ENV->PC has already been updated.  */
void QEMU_NORETURN helper_excp(int excp, int error)
{
    env->exception_index = excp;
    env->error_code = error;
    cpu_loop_exit(env);
}




/*****************************************************************************/
/* Softmmu support */

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




/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
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
