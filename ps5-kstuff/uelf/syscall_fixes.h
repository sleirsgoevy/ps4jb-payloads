#pragma once
#include <sys/types.h>

#define SYS_mdbg_call 573

void handle_syscall_fix(uint64_t* regs);
int try_handle_syscall_fix_trap(uint64_t* regs);
