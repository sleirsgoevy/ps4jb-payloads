#include "dbg.h"
#include <sys/thr.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <machine/sysarch.h>

void k_get_td(void* td, void*** uap)
{
    uap[1][0] = td;
}

void k_get_xfast_syscall(void* td, void*** uap)
{
    uint32_t low, high, which = 0xc0000082;
    asm volatile("rdmsr":"=a"(low),"=d"(high):"c"(which));
    uap[1][0] = (void*)((uint64_t)high << 32 | low);
}

void k_patch_kernel(void* td, void*** uap)
{
    asm volatile("mov %%cr0, %%rax\nbtc $16, %%eax\nmov %%rax, %%cr0":::"rax");
    char* dst = uap[1][0];
    char* src = uap[1][1];
    size_t sz = (size_t)uap[1][2];
    for(size_t i = 0; i < sz; i++)
        dst[i] = src[i];
    asm volatile("mov %%cr0, %%rax\nbts $16, %%eax\nmov %%rax, %%cr0":::"rax");
}

void kexec(void*, void*);

void* get_td(void)
{
    void* ans;
    kexec(k_get_td, &ans);
    return ans;
}

void* get_xfast_syscall(void)
{
    void* ans;
    kexec(k_get_xfast_syscall, &ans);
    return ans;
}

void patch_kernel(void* addr, char* src, size_t sz)
{
    void* payload[3] = {addr, src, (void*)sz};
    kexec(k_patch_kernel, payload);
}

void sidt(unsigned char* p)
{
    asm volatile("sidt (%0)"::"r"(p));
}

void* malloc(size_t sz)
{
    return mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

int main(void)
{
    dbg_enter();
    //detect being injected
    void* fsbase = 0;
    sysarch(AMD64_GET_FSBASE, &fsbase);
    if(!fsbase)
        thr_exit(0);
    return 0;
}
