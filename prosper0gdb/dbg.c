#define __PS4__
#define MEM_HELPERS
#define INTERRUPTER_THREAD
#define NO_BREAKPOINT_EMULATION
#include "../gdb_stub/dbg.c"

ssize_t copyin(uint64_t dst, const void* src, size_t count);
ssize_t copyout(void* dst, uint64_t src, size_t count);

extern uint64_t kdata_base;

int read_mem(unsigned char* buf, unsigned long long addr, int sz)
{
    if(addr >= 0xffffffff00000000 && addr < kdata_base)
        return -14;
    if(copyout(buf, addr, sz) != sz)
        return -errno;
    return 0;
}

static int write_mem(const unsigned char* buf, unsigned long long addr, int sz)
{
    if(addr >= 0xffffffff00000000 && addr < kdata_base)
        return -14;
    if(copyin(addr, buf, sz) != sz)
        return -errno;
    return 0;
}
