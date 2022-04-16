#include <sys/types.h>
#include <sys/thr.h>
#include <sys/mman.h>
#include <stdint.h>
#include "trap_state.h"

extern char r0hook_start[];
extern char r0hook_int1[];
extern char r0hook_int3[];
extern char r0hook_real_int1[];
extern char r0hook_real_int3[];
extern char r0hook_mailbox[];
extern char r0hook_end[];

void kexec(void*, void*);

static uintptr_t replace_interrupt(int which, uintptr_t new)
{
    struct
    {
        uint16_t size;
        uint16_t* ptr;
    } __attribute__((packed)) idtr;
    asm volatile("sidt (%0)"::"r"(&idtr));
    uintptr_t old = (uintptr_t)idtr.ptr[which*8+5] << 48
                  | (uintptr_t)idtr.ptr[which*8+4] << 32
                  | (uintptr_t)idtr.ptr[which*8+3] << 16
                  | (uintptr_t)idtr.ptr[which*8];
    idtr.ptr[which*8] = new;
    idtr.ptr[which*8+3] = new >> 16;
    idtr.ptr[which*8+4] = new >> 32;
    idtr.ptr[which*8+5] = new >> 48;
    return old;
}

static volatile char* get_r0hook_base(void)
{
    static volatile char* ans;
    if(ans)
        return ans;
    uint32_t high;
    uint32_t low;
    asm volatile("rdmsr":"=a"(low),"=d"(high):"c"(0xc0000082));
    char* kernel_base = (char*)(((uint64_t)high) << 32 | low) - 0x1c0; //elf header should be safe to overwrite
    char* phdr = kernel_base + *(uint64_t*)(kernel_base + 32);
    uint16_t phnum = *(uint16_t*)(kernel_base + 56);
    for(size_t i = 0; i < phnum; i++)
    {
        char* phent = phdr + 56 * i;
        if(*(uint32_t*)phent == 2)
        {
            char* dyn_start_c = *(char**)(phent+16);
            char* dyn_end_c = dyn_start_c + *(uint64_t*)(phent+40);
            uint64_t* dyn_start = (uint64_t*)dyn_start_c;
            uint64_t* dyn_end = (uint64_t*)dyn_end_c;
            for(uint64_t* cur = dyn_start; cur + 2 <= dyn_end; cur += 2)
            {
                if(cur[0] == 0x61000025)
                    return ans = (volatile char*)(kernel_base + (cur[1] - 0xffffffff82200000));
            }
        }
    }
    *(void* volatile*)0;
}

#define DISABLE_WP() asm volatile("cli\nmov %%cr0, %%rax\nbtc $16, %%rax\nmov %%rax, %%cr0":::"rax")
#define ENABLE_WP() asm volatile("mov %%cr0, %%rax\nbts $16, %%rax\nmov %%rax, %%cr0\nsti":::"rax")

static void install_code(void)
{
    volatile char* kernel_base = get_r0hook_base();
    DISABLE_WP();
    for(char* i = r0hook_start; i < r0hook_end; i++)
        kernel_base[i - r0hook_start] = *i;
    *(volatile uint64_t*)(kernel_base + (r0hook_real_int1 - r0hook_start)) = replace_interrupt(1, (uintptr_t)(kernel_base + (r0hook_int1 - r0hook_start)));
    *(volatile uint64_t*)(kernel_base + (r0hook_real_int3 - r0hook_start)) = replace_interrupt(3, (uintptr_t)(kernel_base + (r0hook_int3 - r0hook_start)));
    ENABLE_WP();
}

struct mailbox
{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t int_no;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rax;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

static void read_mailbox(void* p, struct mailbox*** dst)
{
    volatile char* kernel_base = get_r0hook_base();
    dst[1][0] = *(struct mailbox* volatile*)(kernel_base + (r0hook_mailbox - r0hook_start));
}

static void write_mailbox(void* p, struct mailbox** src)
{
    volatile char* kernel_base = get_r0hook_base();
    DISABLE_WP();
    *(struct mailbox* volatile*)(kernel_base + (r0hook_mailbox - r0hook_start)) = src[1];
    ENABLE_WP();
}

static void copy_from_kernel(void* p, struct mailbox*** q)
{
    q[1][0][0] = q[1][1][0];
}

static void copy_to_kernel(void* p, struct mailbox*** q)
{
    DISABLE_WP();
    q[1][1][0] = q[1][0][0];
    ENABLE_WP();
}

extern int in_signal_handler;

int gdbstub_main_loop(struct trap_state* ts, ssize_t* result, int* ern);

static void ring0_mailbox_thread(void* ptr)
{
    for(;;)
    {
        struct mailbox* mb;
        while(!(kexec(read_mailbox, &mb), mb && mb != (struct mailbox*)1));
        struct mailbox data;
        void* req[2] = {&data, mb};
        kexec(copy_from_kernel, req);
        struct trap_state ts = {
            .trap_signal = SIGTRAP,
            .regs = {
                .rax = data.rax,
                .rcx = data.rcx,
                .rdx = data.rdx,
                .rbx = data.rbx,
                .rsp = data.rsp,
                .rbp = data.rbp,
                .rsi = data.rsi,
                .rdi = data.rdi,
                .r8 = data.r8,
                .r9 = data.r9,
                .r10 = data.r10,
                .r11 = data.r11,
                .r12 = data.r12,
                .r13 = data.r13,
                .r14 = data.r14,
                .r15 = data.r15,
                .rip = data.rip,
                .cs = data.cs,
                .eflags = data.rflags & ~256ull,
                .ss = data.cs,
            },
        };
        if(data.int_no == 3)
            ts.regs.rip--;
        while(__atomic_exchange_n(&in_signal_handler, 1, __ATOMIC_ACQUIRE));
        gdbstub_main_loop(&ts, 0, 0);
        __atomic_exchange_n(&in_signal_handler, 0, __ATOMIC_RELEASE);
        data.rax = ts.regs.rax;
        data.rcx = ts.regs.rcx;
        data.rdx = ts.regs.rdx;
        data.rbx = ts.regs.rbx;
        data.rsp = ts.regs.rsp;
        data.rbp = ts.regs.rbp;
        data.rsi = ts.regs.rsi;
        data.rdi = ts.regs.rdi;
        data.r8 = ts.regs.r8;
        data.r9 = ts.regs.r9;
        data.r10 = ts.regs.r10;
        data.r11 = ts.regs.r11;
        data.r12 = ts.regs.r12;
        data.r13 = ts.regs.r13;
        data.r14 = ts.regs.r14;
        data.r15 = ts.regs.r15;
        data.rip = ts.regs.rip;
        data.rflags = ts.regs.eflags;
        kexec(copy_to_kernel, req);
        mb = (struct mailbox*)1;
        kexec(write_mailbox, mb);
    }
}

void start_ring0(void)
{
    char* stack = mmap(0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    long x, y;
    struct thr_param param = {
        .start_func = ring0_mailbox_thread,
        .arg = 0,
        .stack_base = stack,
        .stack_size = 16384,
        .tls_base = 0,
        .tls_size = 0,
        .child_tid = &x,
        .parent_tid = &y,
        .flags = 0,
        .rtp = 0
    };
    thr_new(&param, sizeof(param));
}

void install_ring0(void)
{
    kexec(install_code, 0);
}
