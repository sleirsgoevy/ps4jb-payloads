#pragma once

struct regs
{
    unsigned long long rax;
    unsigned long long rbx;
    unsigned long long rcx;
    unsigned long long rdx;
    unsigned long long rsi;
    unsigned long long rdi;
    unsigned long long rbp;
    unsigned long long rsp;
    unsigned long long r8;
    unsigned long long r9;
    unsigned long long r10;
    unsigned long long r11;
    unsigned long long r12;
    unsigned long long r13;
    unsigned long long r14;
    unsigned long long r15;
    unsigned long long rip;
    unsigned int eflags;
    unsigned int cs;
    unsigned int ss;
    unsigned int ds;
    unsigned int es;
    unsigned int fs;
    unsigned int gs;
};

struct trap_state
{
    int trap_signal;
    struct regs regs;
};
