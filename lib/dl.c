// https://gist.github.com/flatz/1055a8d7819c8478db1b464842582c9c
#include <sys/types.h>
#include <stddef.h>

int (*p_sceKernelLoadStartModule)(const char* path, long, long, long, long, long);

int dynlib_dlsym(int, const char*, void**);

void* dlsym(void* handle, const char* name)
{
    void* addr = 0;
    dynlib_dlsym((int)(long long)handle, name, &addr);
    return addr;
}

void* dlopen(const char* path, int mode)
{
    if(!p_sceKernelLoadStartModule)
        p_sceKernelLoadStartModule = dlsym((void*)0x1, "sceKernelLoadStartModule");
    return (void*)(long long)p_sceKernelLoadStartModule(path, 0, 0, 0, 0, 0);
}
