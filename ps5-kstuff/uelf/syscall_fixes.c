#include "utils.h"
#include "syscall_fixes.h"

extern char mprotect_fix_start[];
extern char mprotect_fix_end[];
extern char mdbg_call_fix[];

static uint64_t dbgregs_for_syscall_fix[6] = {
    (uint64_t)mprotect_fix_start, (uint64_t)mdbg_call_fix, 0, 0,
    0, 0x405,
};

void handle_syscall_fix(uint64_t* regs)
{
    start_syscall_with_dbgregs(regs, dbgregs_for_syscall_fix);
}

int try_handle_syscall_fix_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)mprotect_fix_start)
        regs[RIP] = (uint64_t)mprotect_fix_end;
    else if(regs[RIP] == (uint64_t)mdbg_call_fix)
        regs[RAX] = 1;
    else
        return 0;
    return 1;
}
