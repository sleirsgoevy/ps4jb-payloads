#pragma once
#include <machine/pcb.h>
#include "../structs.h"

enum
{
    RAX = iret_rax/8,
    RCX = iret_rcx/8,
    RDX = iret_rdx/8,
    RBX = iret_rbx/8,
    RBP = iret_rbp/8,
    RSI = iret_rsi/8,
    RDI = iret_rdi/8,
    R8 = iret_r8/8,
    R9 = iret_r9/8,
    R10 = iret_r10/8,
    R11 = iret_r11/8,
    R12 = iret_r12/8,
    R13 = iret_r13/8,
    R14 = iret_r14/8,
    R15 = iret_r15/8,
    RIP = iret_rip/8,
    CS,
    EFLAGS,
    RSP,
    SS,
    NREGS,
    ERRC = RIP - 1,
};
