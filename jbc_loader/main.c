#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/mman.h>
#define pid_t jbc_pid_t
#include "ps4-libjbc/jailbreak.h"
#undef pid_t

void* dlopen(const char* path, int mode);
void* dlsym(void* handle, const char* name);

int main()
{
    struct jbc_cred cr;
    jbc_get_cred(&cr);
    jbc_jailbreak_cred(&cr);
    jbc_set_cred(&cr);
    void* handle = dlopen("/system/common/lib/libSceSysUtil.sprx", 0);
    int(*sceSysUtilSendSystemNotificationWithText)(int, const char*) = dlsym(handle, "sceSysUtilSendSystemNotificationWithText");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
        goto bind_failed;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = 0},
        .sin_port = 0x3d23, //9021
    };
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)))
        goto bind_failed;
    if(listen(sock, 1))
        goto bind_failed;
    sceSysUtilSendSystemNotificationWithText(222, "[jbc_loader] waiting for payloads");
    int sock2 = accept(sock, 0, 0);
    if(sock2 < 0)
    {
        sceSysUtilSendSystemNotificationWithText(222, "[jbc_loader] accept failed");
        return 1;
    }
    void* mem = 0;
    size_t sz = 0;
    size_t off = 0;
    for(;;)
    {
        if(off == sz)
        {
            size_t new_sz = sz * 2;
            if(!new_sz)
                new_sz = 0x4000;
            void* new_mem = mmap(0, new_sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
            char* new_s = new_mem;
            char* old_s = mem;
            for(size_t i = 0; i < sz; i++)
                new_s[i] = old_s[i];
            if(mem)
                munmap(mem, sz);
            sz = new_sz;
            mem = new_mem;
        }
        ssize_t chk = read(sock2, (char*)mem + off, sz - off);
        if(chk <= 0)
            break;
        off += chk;
    }
    sceSysUtilSendSystemNotificationWithText(222, "[jbc_loader] launching payload");
    ((void(*)(void))mem)();
    return 0;
bind_failed:
    sceSysUtilSendSystemNotificationWithText(222, "[jbc_loader] bind failed");
    return 0;
}
