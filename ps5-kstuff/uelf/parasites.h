extern char kdata_base[];

static int handle_syscall_parasites(uint64_t* regs)
{
#ifndef FREEBSD
    if(regs[RIP] == (uint64_t)kdata_base - 0x80284d)
        regs[RDI] |= 0xffffull << 48;
    else if(regs[RIP] == (uint64_t)kdata_base - 0x3889ac)
        regs[RSI] |= 0xffffull << 48;
    else if(regs[RIP] == (uint64_t)kdata_base - 0x38896c)
        regs[RSI] |= 0xffffull << 48;
    else
        return 0;
    return 1;
#else
    return 0;
#endif
}

static int handle_fself_parasites(uint64_t* regs)
{
#ifndef FREEBSD
    if(regs[RIP] == (uint64_t)kdata_base - 0x2cc716
    || regs[RIP] == (uint64_t)kdata_base - 0x2cd28a
    || regs[RIP] == (uint64_t)kdata_base - 0x2cd150)
        regs[RAX] |= 0xffffull << 48;
    else if(regs[RIP] == (uint64_t)kdata_base - 0x2cc882)
        regs[RCX] |= 0xffffull << 48;
    else if(regs[RIP] == (uint64_t)kdata_base - 0x990b10)
        regs[RDI] |= 0xffffull << 48;
    else
        return 0;
    return 1;
#else
    return 0;
#endif
}
