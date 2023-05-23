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

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
    dbg_enter();
    return 0; //p r0gdb() for magic
}
