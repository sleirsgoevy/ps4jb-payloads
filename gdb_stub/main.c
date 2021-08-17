#include "dbg.h"
#include <sys/thr.h>
#include <sys/mman.h>
#include <sys/types.h>

void k_get_td(void* td, void*** uap)
{
    uap[1][0] = td;
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

void patch_kernel(void* addr, char* src, size_t sz)
{
    void* payload[3] = {addr, src, (void*)sz};
    kexec(k_patch_kernel, payload);
}

void* malloc(size_t sz)
{
    return mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

int main(void)
{
    dbg_enter();
    thr_exit(0);
}
