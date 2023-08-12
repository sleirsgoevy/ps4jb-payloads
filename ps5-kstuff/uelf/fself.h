#pragma once
#include <sys/types.h>
#include <sys/syscall.h>

#define SYS_execve 59
#define SYS_dynlib_load_prx 594
#define SYS_get_self_auth_info 607
#define SYS_get_sdk_compiled_version 647
#define SYS_get_ppr_sdk_compiled_version 713

void handle_fself_syscall(uint64_t* regs);
void handle_fself_trap(uint64_t* regs, uint32_t trapno);
int try_handle_fself_trap(uint64_t* regs);
