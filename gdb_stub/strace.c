#define sysctl __sysctl
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/thr.h>
#include <sys/socket.h>
#include "dbg.h"

int is_syscall_wrapper(uint8_t* p)
{
    if(p[0] == 0x48
    && p[1] == 0xc7
    && p[2] == 0xc0
    && p[7] == 0x49
    && p[8] == 0x89
    && p[9] == 0xca
    && p[10] == 0x0f
    && p[11] == 0x05)
        return *(volatile int32_t*)(p+3);
    return -1;
}

static int strace_pipe[2];

void log_syscall_args(uint64_t* args)
{
    char buf[256];
    char* p = buf;
    uint64_t nr = args[0];
    uint64_t i = 1;
    while((i * 10) / 10 == i && nr / i >= 10)
        i *= 10;
    while(i)
    {
        *p++ = '0' + (nr / i) % 10;
        i /= 10;
    }
    *p++ = '(';
    for(int i = 1; i <= 6; i++)
    {
        uint64_t q = args[i];
        *p++ = '0';
        *p++ = 'x';
        int j = 0;
        while(j < 60 && (q >> j) >= 16)
            j += 4;
        for(; j >= 0; j -= 4)
            *p++ = "0123456789abcdef"[(q >> j) & 15];
        if(i != 6)
        {
            *p++ = ',';
            *p++ = ' ';
        }
    }
    *p++ = ')';
    write(strace_pipe[1], buf, p-buf);
}

void log_syscall_ans(uint64_t ans, uint64_t flags)
{
    char buf[64];
    char* p = buf;
    *p++ = ' ';
    *p++ = '=';
    *p++ = ' ';
    if((flags & 1))
    {
        char* s = "-1, errno = ";
        while(*s)
            *p++ = *s++;
        uint64_t q = 1;
        while((q * 10) / 10 == q && ans / q >= 10)
            q *= 10;
        while(q)
        {
            *p++ = '0' + (ans / q) % 10;
            q /= 10;
        }
    }
    else
    {
        *p++ = '0';
        *p++ = 'x';
        int i = 0;
        while(i < 60 && (ans >> i) >= 16)
            i += 4;
        for(; i >= 0; i -= 4)
            *p++ = "0123456789abcdef"[(ans >> i) & 15];
    }
    *p++ = '\n';
    write(strace_pipe[1], buf, p-buf);
}

extern char strace_log_start[];
extern char strace_log_end[];

void strace_thread(void* arg)
{
    char buf[1024];
    ssize_t chk;
    for(;;)
    {
        chk = read(strace_pipe[0], buf, 1024);
        if(chk > 0)
            gdb_remote_syscall("write", 3, NULL, (uintptr_t)2, (uintptr_t)buf, (uintptr_t)chk);
    }
}

void start_strace(char* start, char* end)
{
    socketpair(AF_UNIX, SOCK_STREAM, 0, strace_pipe);
    long x, y;
    struct thr_param param = {
        .start_func = strace_thread,
        .arg = NULL,
        .stack_base = mmap(0, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0),
        .stack_size = 65536,
        .tls_base = NULL,
        .tls_size = 0,
        .child_tid = &x,
        .parent_tid = &y,
        .flags = 0,
        .rtp = NULL,
    };
    thr_new(&param, sizeof(param));
    size_t nsys = 0;
    for(char* i = start; i + 12 <= end; i++)
        if(is_syscall_wrapper((uint8_t*)i) >= 0)
        {
            nsys++;
            i += 11;
        }
    size_t jitsz = nsys * (6+2+6+8+8+8+4);
    void* jit = mmap(0, jitsz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    char* jitp = jit;
    for(char* i = start; i + 12 <= end; i++)
    {
        int sysno;
        if((sysno = is_syscall_wrapper((uint8_t*)i)) >= 0)
        {
            char* addr = jitp;
            *jitp++ = 0xff;
            *jitp++ = 0x15;
            *jitp++ = 2+6;
            *jitp++ = 0;
            *jitp++ = 0;
            *jitp++ = 0;
            *jitp++ = 0x0f;
            *jitp++ = 0x05;
            *jitp++ = 0xff;
            *jitp++ = 0x15;
            *jitp++ = 8;
            *jitp++ = 0;
            *jitp++ = 0;
            *jitp++ = 0;
            *(uint64_t*)jitp = (uint64_t)strace_log_start;
            *(uint64_t*)(jitp+8) = (uint64_t)strace_log_end;
            *(uint64_t*)(jitp+16) = (uint64_t)(i+12);
            *(int32_t*)(jitp+24) = sysno;
            jitp += 28;
            uint64_t low = (uint64_t)i;
            uint64_t high = (uint64_t)(i+12);
            mprotect((void*)(low & ~0x3fffull), high-low, PROT_READ|PROT_WRITE|PROT_EXEC);
            *(uint16_t*)i = 0xfeeb;
            *(uint64_t*)(i+2) = (uint64_t)addr;
            *(uint16_t*)(i+10) = 0xe0ff;
            *(uint16_t*)i = 0xb848;
            i += 11;
        }
    }
}
