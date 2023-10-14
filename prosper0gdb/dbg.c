#define __PS4__
#ifndef NO_MEM_HELPERS
#define MEM_HELPERS
#endif
#define INTERRUPTER_THREAD
#define NO_BREAKPOINT_EMULATION
#include "../gdb_stub/dbg.c"

ssize_t copyin(uint64_t dst, const void* src, size_t count);
ssize_t copyout(void* dst, uint64_t src, size_t count);

extern uint64_t kdata_base;
extern uint64_t rpipe;

#ifdef MEM_HELPERS
int read_mem(unsigned char* buf, unsigned long long addr, int sz)
{
#ifdef MEMRW_FALLBACK
    if(!rpipe)
    {
        if(write(pipe_w, (void*)addr, sz) != sz)
            return -14;
        read(pipe_r, buf, sz);
        return 0;
    }
#endif
    if(addr >= 0xffffffff00000000 && addr < kdata_base)
        return -14;
    if(copyout(buf, addr, sz) != sz)
        return -errno;
    return 0;
}

static int write_mem(const unsigned char* buf, unsigned long long addr, int sz)
{
#ifdef MEMRW_FALLBACK
    if(!rpipe)
    {
        write(pipe_w, buf, sz);
        if(read(pipe_r, (void*)addr, sz) != sz)
        {
            char c;
            for(int i = 0; i < sz; i++)
                read(pipe_r, &c, 1);
            return -14;
        }
        return 0;
    }
#endif
    if(addr >= 0xffffffff00000000 && addr < kdata_base)
        return -14;
    if(copyin(addr, buf, sz) != sz)
        return -errno;
    return 0;
}
#endif
