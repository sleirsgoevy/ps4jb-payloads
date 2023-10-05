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
#include "mailbox.h"
#include "fself.h"
#include "fpkg.h"
#include "syscall_fixes.h"

int have_error_code;

extern char syscall_before[];
extern char syscall_after[];
extern struct sysent sysents[];
extern struct sysent sysents2[];
extern char doreti_iret[];
extern char ist4[];
extern char tss[];
extern char int1_handler[];
extern char int13_handler[];
extern uint64_t wrmsr_args;

void handle_syscall(uint64_t* regs, int allow_kekcall)
{
#define IS_PPR(which) (regs[RAX] == (uint64_t)&sysents[SYS_##which])
#ifdef FREEBSD
#define IS_PS4(which) 0
#else
#define IS_PS4(which) (regs[RAX] == (uint64_t)&sysents2[SYS_##which])
#endif
#define IS(which) (IS_PPR(which) || IS_PS4(which))
    if(IS_PPR(getppid) && allow_kekcall)
    {
        uint64_t args[NREGS] = {0};
        copy_from_kernel(args, regs[RSP]+syscall_rsp_to_regs_stash+8, sizeof(args));
        int err = handle_kekcall(regs, args, args[RAX]>>32);
        if(err != ENOSYS)
        {
            if(!err)
                kpoke64(regs[RDI]+td_retval, args[RAX]);
            regs[RAX] = err;
            pop_stack(regs, &regs[RIP], 8);
        }
    }
#ifndef FREEBSD
    else if(IS(execve)
         || IS(dynlib_load_prx)
         || IS(get_self_auth_info)
         || IS(get_sdk_compiled_version)
         || IS_PPR(get_ppr_sdk_compiled_version))
        handle_fself_syscall(regs);
    else if(IS(nmount)
         || IS(unmount))
        handle_fpkg_syscall(regs);
    else if(IS(mprotect)
         || IS_PPR(mdbg_call))
        handle_syscall_fix(regs);
#endif
#undef IS
#undef IS_PS4
#undef IS_PPR
}

void handle(uint64_t* regs)
{
    if(!(regs[CS] & 3))
        regs[EFLAGS] |= 0x10000; //RF
    if((regs[CS] & 3) || (regs[EFLAGS] & 0x40000)) //from userspace, or from copyin/copyout
    {
from_userspace:
        if((regs[CS] & 3)) //from userspace
        {
            //determine correct gsbase for userspace
            uint64_t gsbase = kpeek64(kpeek64(kpeek64((uint64_t)pcpu)+td_pcb)+pcb_gsbase);
            //arm wrmsr in the exit path
            uint64_t args[3] = {gsbase >> 32, 0xc0000101, (uint32_t)gsbase};
            copy_to_kernel(wrmsr_args, args, sizeof(args));
        }
        //inject a fake #DB or #GP exception
        uint64_t stack;
#ifndef FREEBSD
        if(!have_error_code)
            stack = (uint64_t)ist4;
        else
#endif
        {
            if((regs[CS] & 3))
                copy_from_kernel(&stack, (uint64_t)tss+4, 8);
            else
                stack = regs[RSP];
        }
        stack &= -16;
        if(have_error_code)
        {
            stack -= 48;
            copy_to_kernel(stack, &regs[ERRC], 48);
            regs[RIP] = (uint64_t)int13_handler;
        }
        else
        {
            stack -= 40;
            copy_to_kernel(stack, &regs[RIP], 40);
            regs[RIP] = (uint64_t)int1_handler;
        }
        regs[CS] = 0x20;
        regs[EFLAGS] = 2;
        regs[RSP] = stack;
        regs[SS] = 0;
    }
    else if(handle_syscall_parasites(regs))
        return;
    else if(regs[RIP] == (uint64_t)syscall_before)
    {
        regs[RAX] |= 0xffffull << 48;
        regs[RSI] = regs[RSP] + syscall_rsp_to_rsi;
        push_stack(regs, (const uint64_t[1]){(uint64_t)syscall_after}, 8);
        regs[RIP] = kpeek64(regs[RAX]+8);
        handle_syscall(regs, 1);
    }
    else if(regs[RIP] == (uint64_t)doreti_iret)
    {
        uint64_t frame[5];
        copy_from_kernel(frame, regs[RSP], sizeof(frame));
        if((frame[1] & 3)) //#GP in iret to userspace
        {
            //pretend that the #GP was inside userspace
            //stock kernel crashes on this, lol
            memcpy(&regs[RIP], frame, sizeof(frame));
            goto from_userspace;
        }
        uint64_t lr = frame[0];
        switch(TRAP_KIND(lr))
        {
        case TRAP_UTILS: handle_utils_trap(regs, TRAP_IDX(lr)); break;
        case TRAP_KEKCALL: handle_kekcall_trap(regs, TRAP_IDX(lr)); break;
#ifndef FREEBSD
        case TRAP_FSELF: handle_fself_trap(regs, TRAP_IDX(lr)); break;
        case TRAP_FPKG: handle_fpkg_trap(regs, TRAP_IDX(lr)); break;
#endif
        }
    }
#ifndef FREEBSD
    else if(try_handle_mailbox_trap(regs))
        return;
    else if(try_handle_fself_trap(regs))
        return;
    else if(handle_fself_parasites(regs))
        return;
    else if(handle_unsorted_parasites(regs))
        return;
    else if(try_handle_fpkg_trap(regs))
        return;
    else if(try_handle_syscall_fix_trap(regs))
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
    handle(regs);
    copy_to_kernel(trap_frame, regs, sizeof(regs));
}
