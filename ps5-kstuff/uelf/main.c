#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include "utils.h"
#include "parasites.h"
#include "log.h"
#include "traps.h"
#include "kekcall.h"
#include "fself.h"

int have_error_code;

extern char syscall_before[];
extern char syscall_after[];
extern struct sysent sysents[];
extern struct sysent sysents2[];
extern char doreti_iret[];

void handle(uint64_t* regs)
{
    if(handle_syscall_parasites(regs))
        return;
    else if(regs[RIP] == (uint64_t)syscall_before)
    {
        regs[RAX] |= 0xffffull << 48;
#define IS_PPR(which) (regs[RAX] == (uint64_t)&sysents[SYS_##which])
#ifdef FREEBSD
#define IS_PS4(which) 0
#else
#define IS_PS4(which) (regs[RAX] == (uint64_t)&sysents2[SYS_##which])
#endif
#define IS(which) (IS_PPR(which) || IS_PS4(which))
        if(IS_PPR(getppid))
        {
            uint64_t args[NREGS] = {0};
            copy_from_kernel(args, regs[RSP]+syscall_rsp_to_regs_stash, sizeof(args));
            int err = handle_kekcall(regs, args, args[RAX]>>32);
            if(err != ENOSYS)
            {
                if(!err)
                    kpoke64(regs[RDI]+td_retval, args[RAX]);
                regs[RAX] = err;
                regs[RIP] = (uint64_t)syscall_after;
            }
        }
#ifndef FREEBSD
        else if(IS(execve)
             || IS(dynlib_load_prx)
             || IS(get_self_auth_info)
             || IS(get_sdk_compiled_version)
             || IS_PPR(get_ppr_sdk_compiled_version))
            handle_fself_syscall(regs);
#endif
#undef IS
#undef IS_PS4
#undef IS_PPR
    }
    else if(regs[RIP] == (uint64_t)doreti_iret)
    {
        uint64_t lr = kpeek64(regs[RSP]);
        switch(TRAP_KIND(lr))
        {
        case TRAP_UTILS: handle_utils_trap(regs, TRAP_IDX(lr)); break;
        case TRAP_KEKCALL: handle_kekcall_trap(regs, TRAP_IDX(lr)); break;
#ifndef FREEBSD
        case TRAP_FSELF: handle_fself_trap(regs, TRAP_IDX(lr)); break;
#endif
        }
    }
#ifndef FREEBSD
    else if(try_handle_fself_trap(regs))
        return;
    else if(handle_fself_parasites(regs))
        return;
#endif
    else
    {
        int decrypted = 0;
#define DECRYPT(which, idx) if((regs[which] >> 48) == 0xdeb7) { log_word(regs[RIP]); log_word(idx); regs[which] |= 0xffffull << 48; decrypted = 1; }
        DECRYPT(RAX, 0)
        DECRYPT(RCX, 1)
        DECRYPT(RDX, 2)
        DECRYPT(RBX, 3)
        //DECRYPT(RSP, 4)
        DECRYPT(RBP, 5)
        DECRYPT(RSI, 6)
        DECRYPT(RDI, 7)
        DECRYPT(R8, 8)
        DECRYPT(R9, 9)
        DECRYPT(R10, 10)
        DECRYPT(R11, 11)
        DECRYPT(R12, 12)
        DECRYPT(R13, 13)
        DECRYPT(R14, 14)
        DECRYPT(R15, 15)
#undef DECRYPT
        if(!decrypted)
        {
            //probably a debug trap that's not yet handled
            log_word(regs[RIP]);
            log_word(16);
        }
    }
}

void main(uint64_t just_return)
{
    uint64_t regs[NREGS];
    copy_from_kernel(regs, trap_frame, sizeof(regs));
    uint64_t jr_frame[5];
    copy_from_kernel(jr_frame, just_return, 40);
    have_error_code = jr_frame[0];
    regs[RDX] = jr_frame[2];
    regs[RCX] = jr_frame[3];
    regs[RAX] = jr_frame[4];
    if(!(regs[CS] & 3))
        regs[EFLAGS] |= 0x10000; //RF
    handle(regs);
    if((regs[CS] & 3)) //we've interrupted userspace
    {
        //determine correct gsbase for userspace
        uint64_t gsbase = kpeek64(kpeek64(kpeek64((uint64_t)pcpu)+td_pcb)+pcb_gsbase);
        wrmsr(0xc0000102, gsbase); //the final iret will swapgs it
    }
    copy_to_kernel(trap_frame, regs, sizeof(regs));
}
