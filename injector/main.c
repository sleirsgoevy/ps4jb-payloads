#define sysctl __sysctl

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/thr.h>

#define _KERNEL
#include <sys/uio.h>
#include <ps4-offsets/kernel.h>

asm("kexec:\nmov $11, %rax\nmov %rcx, %r10\nsyscall\nret");
void kexec(void*, void*);

unsigned long long k_xfast_syscall()
{
    unsigned int a, c = 0xc0000082;
    unsigned long long d;
    asm volatile("rdmsr":"=a"(a),"=d"(d):"c"(c));
    return d << 32 | a;
}

unsigned long long k_read64(unsigned long long ptr)
{
    return *(volatile unsigned long long*)ptr;
}

unsigned long long k_read8(unsigned long long ptr)
{
    return *(volatile unsigned char*)ptr;
}

asm("k_curthread:\nmov %fs:0, %rax\nret");
extern char k_curthread[];

void k_call(void* td, unsigned long long** uap)
{
    uap[1][0] = ((unsigned long long(*)(unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long))uap[1][0])(uap[1][1], uap[1][2], uap[1][3], uap[1][4], uap[1][5], uap[1][6]);
}

unsigned long long kcall(void* fn, ...)
{
    va_list v;
    va_start(v, fn);
    unsigned long long args[7];
    args[0] = (unsigned long long)fn;
    args[1] = va_arg(v, unsigned long long);
    args[2] = va_arg(v, unsigned long long);
    args[3] = va_arg(v, unsigned long long);
    args[4] = va_arg(v, unsigned long long);
    args[5] = va_arg(v, unsigned long long);
    args[6] = va_arg(v, unsigned long long);
    va_end(v);
    kexec(k_call, args);
    return args[0];
}

#define kprintf(...) kcall((void*)(kcall(k_xfast_syscall) - kernel_offset_xfast_syscall + kernel_offset_printf), __VA_ARGS__)

void writeall(int fd, const char* buf, size_t cnt)
{
    while(cnt)
    {
        ssize_t chk = write(fd, buf, cnt);
        if(chk <= 0)
            return;
        buf += chk;
        cnt -= chk;
    }
}

void readall(int fd, char* buf, size_t cnt)
{
    while(cnt)
    {
        ssize_t chk = read(fd, buf, cnt);
        if(chk <= 0)
            return;
        buf += chk;
        cnt -= chk;
    }
}

void ps_pid(int socket, pid_t pid)
{
    int q[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    char dump[4096];
    size_t sz = 4096;
    sysctl(q, 4, dump, &sz, NULL, 0);
    char* proc_name = dump + 0x1bf;
    off_t o = 0;
    while(proc_name[o])
        o++;
    *(pid_t*)(proc_name - sizeof(off_t) - sizeof(pid_t)) = pid;
    *(off_t*)(proc_name - sizeof(off_t)) = o;
    writeall(socket, proc_name - sizeof(off_t) - sizeof(pid_t), sizeof(off_t) + sizeof(pid_t) + o);
}

void ps(int socket)
{
    for(unsigned long long proc = kcall(k_read64, kcall(k_xfast_syscall) - kernel_offset_xfast_syscall + kernel_offset_allproc); proc; proc = kcall(k_read64, proc))
        ps_pid(socket, kcall(k_read64, proc + 0xb0));
    char buf[sizeof(off_t) + sizeof(pid_t)] = {0};
    writeall(socket, buf, sizeof(buf));
}

/*off_t k_strcpy(char* a, char* b)
{
    off_t i = 0;
    while((a[i] = ((0x8000000000000000ull&(unsigned long long)(b+i))?b[i]:0)))
        i++;
    return i;
}*/

off_t kstrncpy(char* dst, unsigned long long src, size_t sz)
{
    off_t i = 0;
    while(i < sz && (dst[i] = kcall(k_read8, src + i)))
        i++;
    return i;
}

void do_mmap_pid(int socket, pid_t pid)
{
    unsigned long long proc = kcall(k_read64, kcall(k_xfast_syscall) - kernel_offset_xfast_syscall + kernel_offset_allproc);
    while(proc && kcall(k_read64, proc + 0xb0) != pid)
        proc = kcall(k_read64, proc);
    if(!proc)
        return;
    unsigned long long vmspace = kcall((void*)(kcall(k_xfast_syscall) - kernel_offset_xfast_syscall + kernel_offset_vmspace_acquire_ref), proc);
    unsigned long long vm_entry = kcall(k_read64, vmspace);
    unsigned long long i = vm_entry;
    for(;;)
    {
        unsigned long long j = kcall(k_read64, i);
        if(j == vm_entry)
            break;
        char data[4096];
        off_t start = kcall(k_read64, i+32);
        off_t end = kcall(k_read64, i+40);
        off_t o = kstrncpy(data + 3 * sizeof(off_t), i+141, 4096 - 3 * sizeof(off_t));
        *(off_t*)data = start;
        *(off_t*)(data + sizeof(off_t)) = end;
        *(off_t*)(data + 2 * sizeof(off_t)) = o;
        writeall(socket, data, 3 * sizeof(off_t) + o);
        i = j;
    }
    kcall((void*)(kcall(k_xfast_syscall) - kernel_offset_xfast_syscall + kernel_offset_vmspace_free), vmspace);
}

void mmap_pid(int socket, pid_t pid)
{
    do_mmap_pid(socket, pid);
    off_t buf[3] = {0};
    writeall(socket, (char*)buf, sizeof(buf));
}

void do_inject_payload(pid_t pid, const char* data, size_t len)
{
    unsigned long long sysent = kcall(k_xfast_syscall) - kernel_offset_xfast_syscall + kernel_offset_sysent;
    unsigned long long sys_mmap = kcall(k_read64, sysent + 48 * SYS_mmap + 8);
    unsigned long long sys_thr_new = kcall(k_read64, sysent + 48 * SYS_thr_new + 8);
    unsigned long long proc = kcall(k_read64, kcall(k_xfast_syscall) - kernel_offset_xfast_syscall + kernel_offset_allproc);
    while(proc && kcall(k_read64, proc + 0xb0) != pid)
        proc = kcall(k_read64, proc);
    if(!proc)
        return;
    unsigned long long thread = kcall(k_read64, proc + 16);
    unsigned long long mmap_args[6] = {0, len + 0x10000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0};
    kcall((void*)sys_mmap, thread, mmap_args);
    unsigned long long addr = kcall(k_read64, thread + 0x398);
    struct iovec iov = {
        .iov_base = (void*)data,
        .iov_len = len,
    };
    struct uio uio = {
        .uio_iov = &iov,
        .uio_iovcnt = 1,
        .uio_offset = addr,
        .uio_resid = len,
        .uio_segflg = UIO_SYSSPACE,
        .uio_rw = UIO_WRITE,
        .uio_td = (void*)kcall(k_curthread),
    };
    kcall((void*)(kcall(k_xfast_syscall) - kernel_offset_xfast_syscall + kernel_offset_proc_rwmem), proc, &uio);
    struct thr_param p = {
        .start_func = (void*)addr,
        .arg = 0,
        .stack_base = (void*)(addr + len),
        .stack_size = 0x10000,
        .tls_base = 0,
        .tls_size = 0,
        .child_tid = 0,
        .parent_tid = 0,
        .flags = 0,
        .rtp = 0,
    };
    unsigned long long thr_new_args[] = {(unsigned long long)&p, sizeof(p)};
    kcall((void*)sys_thr_new, thread, thr_new_args);
}

struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr = {.s_addr = 0xb3b3b3b3},
    .sin_port = 0xd204,
};

int main()
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    for(;;)
    {
        int cmd[2] = {0xfee1dead, 0};
        readall(sock, (char*)&cmd, sizeof(cmd));
        if(cmd[0] == 1)
            ps(sock);
        else if(cmd[0] == 2)
            mmap_pid(sock, cmd[1]);
        else if(cmd[0] == 3)
        {
            size_t data_len;
            readall(sock, (char*)&data_len, sizeof(data_len));
            char* data = mmap(0, data_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            readall(sock, data, data_len);
            do_inject_payload(cmd[1], data, data_len);
            munmap(data, data_len);
        }
        else if(cmd[0] == 4)
        {
            kill(cmd[1], SIGKILL);
        }
        else if(cmd[0] == 0xfee1dead)
            break;
    }
    close(sock);
    return 0;
}
