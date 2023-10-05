#pragma once
#include <sys/types.h>
#include <sys/syscall.h>

void handle_fpkg_syscall(uint64_t* regs);
void handle_fpkg_trap(uint64_t* regs, uint32_t trapno);
int try_handle_fpkg_trap(uint64_t* regs);
int try_handle_fpkg_mailbox(uint64_t* regs, uint64_t lr);
