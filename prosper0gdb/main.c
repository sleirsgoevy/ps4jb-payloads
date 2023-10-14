#include "../gdb_stub/dbg.h"
#include "r0gdb.h"
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/mount.h>

void* dlsym(void*, const char*);

void notify(const char* s)
{
    struct
    {
        char pad1[0x10];
        int f1;
        char pad2[0x19];
        char msg[0xc03];
    } notification = {.f1 = -1};
    char* d = notification.msg;
    while(*d++ = *s++);
    ((void(*)())dlsym((void*)0x2001, "sceKernelSendNotificationRequest"))(0, &notification, 0xc30, 0);
}

static void infsleep(int sig)
{
    struct timespec ts = {1000, 0};
    for(;;)
        nanosleep(&ts, 0);
}

void kill_thread(void)
{
    struct sigaction sa = {
        .sa_handler = infsleep,
    };
    sigaction(SIGUSR1, &sa, 0);
    sigset_t ss = {0};
	ss.__bits[_SIG_WORD(SIGUSR1)] |= _SIG_BIT(SIGUSR1);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    for(int i = 0; i < 1000; i++)
        kill(getpid(), SIGUSR1);
}

void ignore_signals(void)
{
    struct sigaction sa = {
        .sa_handler = SIG_IGN,
    };
    for(int i = 1; i < 100; i++)
        if(i != SIGTRAP
        && i != SIGILL
        && i != SIGBUS
        && i != SIGINT
        && i != SIGSYS
        && i != SIGSEGV)
            sigaction20(i, &sa, 0);
}

void* klog_server(void* arg)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = 0 },
        .sin_port = 0x0e27, //9998
    };
    bind(sock, (void*)&sin, sizeof(sin));
    listen(sock, 1);
new_conn:
    int sock2 = accept(sock, NULL, NULL);
    char buf[512];
    int fd1 = open("/dev/klog", O_RDONLY);
    for(;;)
    {
        ssize_t chk = read(fd1, buf, sizeof(buf));
        if(chk < 0)
            break;
        char* p = buf;
        while(chk > 0)
        {
            ssize_t chk1 = write(sock2, p, chk);
            if(chk1 <= 0)
            {
                close(sock2);
                goto new_conn;
            }
            chk -= chk1;
            p += chk1;
        }
    }
}

static void copy_data(int fd1, int fd2)
{
    char buf[4096];
    ssize_t chk;
    while((chk = read(fd1, buf, sizeof(buf))) > 0)
        write(fd2, buf, chk);
}

asm("my_nmount:\nmov $378, %rax\njmp *p_kekcall(%rip)");
void* p_kekcall;
int my_nmount(struct iovec* iov, size_t n, int flags);

void* dlsym(void*, const char*);

int do_nmount(struct iovec* iov, size_t n, int flags)
{
    if(!p_kekcall)
        p_kekcall = dlsym((void*)0x2001, "getppid") + 7;
    return my_nmount(iov, n, flags);
}

int remount_rw(const char* dev, const char* mnt)
{
    size_t n = 0;
    while(dev[n])
        n++;
    size_t m = 0;
    while(mnt[m])
        m++;
    struct iovec iov[] = {
        {"fstype", 7}, {"exfatfs", 8},
        {"fspath", 7}, {(char*)mnt, m+1},
        {"from", 5}, {(char*)dev, n+1},
        {"large", 6}, {"yes", 4},
        {"timezone", 9}, {"static", 7},
        {"async", 6}, {0, 0},
        {"ignoreacl", 10}, {0, 0},
    };
    return do_nmount(iov, 14, MNT_UPDATE);
}

void log_deltas(uint64_t pointer)
{
    for(;;)
    {
        struct regs regs = {0};
        regs.rip = pointer;
        regs.eflags = 0x102;
        run_in_kernel(&regs);
        uint32_t delta = regs.rip - (pointer + 5);
        char buf[9] = {[8] = '\n'};
        for(int i = 0; i < 8; i++)
            buf[i] = "0123456789abcdef"[(delta >> (28-4*i))&15];
        gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)buf, (uintptr_t)9);
        pointer += 8;
    }
}

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
    dbg_enter();
    return 0; //p r0gdb() for magic
}
