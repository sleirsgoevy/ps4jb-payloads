#include "parasite_desc.h"
#include "log.h"

//extern char kdata_base[];

extern struct parasite_desc parasites;

static inline int handle_parasites(uint64_t* regs, int a, int b)
{
    for(int i = a; i < b; i++)
        if(parasites.parasites[i].address == regs[RIP])
        {
            for(int j = i; j < b && parasites.parasites[j].address == regs[RIP]; j++)
                regs[parasites.parasites[j].reg] |= -1ull << 48;
            return 1;
        }
    return 0;
}

static int handle_syscall_parasites(uint64_t* regs)
{
    return handle_parasites(regs, 0, parasites.lim_syscall);
}

static int handle_fself_parasites(uint64_t* regs)
{
    return handle_parasites(regs, parasites.lim_syscall, parasites.lim_fself);
}

static int handle_unsorted_parasites(uint64_t* regs)
{
    return handle_parasites(regs, parasites.lim_fself, parasites.lim_total);
}
