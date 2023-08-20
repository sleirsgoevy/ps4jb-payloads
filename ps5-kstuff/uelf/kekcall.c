#include <errno.h>
#include "kekcall.h"
#include "traps.h"
#include "utils.h"

extern char syscall_after[];
extern char doreti_iret[];
extern char copyout[];
extern char copyin[];

int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr)
{
    if(nr == 1)
    {
        uint64_t stack_frame[13] = {
            (uint64_t)doreti_iret,
            (uint64_t)syscall_after, regs[CS], regs[EFLAGS], regs[RSP], regs[SS],
        };
        read_dbgregs(stack_frame+6);
        if(!get_pcb_dbregs())
        {
            stack_frame[6] = stack_frame[7] = stack_frame[8] = stack_frame[9] = 0;
            stack_frame[10] &= -16;
        }
        push_stack(regs, stack_frame, sizeof(stack_frame));
        kpoke64(regs[RDI]+td_retval, 0);
        regs[RDI] = regs[RSP] + 48;
        regs[RSI] = args[RDI];
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyout;
        return ENOSYS;
    }
    else if(nr == 2)
    {
        uint64_t stack_frame[13] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 1), [12] = regs[RDI]};
        push_stack(regs, stack_frame, sizeof(stack_frame));
        regs[RDI] = args[RDI];
        regs[RSI] = regs[RSP] + 48;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
        return ENOSYS;
    }
    else if(nr == 3)
    {
        return rdmsr(args[RDI], &args[RAX]) ? 0 : EFAULT;
    }
    else if(nr == 0x42)
        regs[CS] |= 1;
    else if(nr == 0xffffffff)
    {
        args[RAX] = 0;
        return 0;
    }
    return ENOSYS;
}

void handle_kekcall_trap(uint64_t* regs, uint32_t trap)
{
    if(trap == 1)
    {
        uint64_t stack_frame[12];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        regs[RIP] = (uint64_t)syscall_after;
        if((uint32_t)regs[RAX])
            return;
        kpoke64(stack_frame[11]+td_retval, 0);
        set_pcb_dbregs();
        write_dbgregs(stack_frame+5);
    }
}
