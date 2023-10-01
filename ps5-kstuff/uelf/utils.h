#pragma once
#include <sys/types.h>
#include <stddef.h>
#include "structs.h"
#include "log.h"

extern uint64_t cr3_phys;
extern uint64_t trap_frame;
extern char pcpu[];

#define DMEM ((char*)(1ull << 39))

int virt2phys(uint64_t addr, uint64_t* phys, uint64_t* phys_limit);
int copy_from_kernel(void* dst, uint64_t src, uint64_t sz);
int copy_to_kernel(uint64_t dst, const void* src, uint64_t sz);
void run_gadget(uint64_t* regs);
void read_dbgregs(uint64_t* dr);
void write_dbgregs(const uint64_t* dr);
void start_syscall_with_dbgregs(uint64_t* regs, const uint64_t* dbgregs);
void handle_utils_trap(uint64_t* regs, uint32_t trapno);
void handle_syscall(uint64_t* regs, int allow_kekcall);
int rdmsr(uint32_t which, uint64_t* ans);
int wrmsr(uint32_t which, uint64_t value);

static inline uint64_t kpeek64(uintptr_t kptr)
{
    uint64_t ans = 0;
    if(copy_from_kernel(&ans, kptr, sizeof(ans)))
        log_word((uint64_t)__builtin_return_address(0));
    return ans;
}

static inline void kpoke64(uintptr_t kptr, uint64_t value)
{
    copy_to_kernel(kptr, &value, sizeof(value));
}

static inline void push_stack(uint64_t* regs, const void* data, size_t sz)
{
    regs[RSP] -= sz;
    copy_to_kernel(regs[RSP], data, sz);
}

static inline void pop_stack(uint64_t* regs, void* data, size_t sz)
{
    copy_from_kernel(data, regs[RSP], sz);
    regs[RSP] += sz;
}

static inline int get_pcb_dbregs(void)
{
    return (kpeek64(kpeek64(kpeek64((uint64_t)pcpu)+td_pcb)+pcb_flags) & PCB_DBREGS) ? 1 : 0;
}

static inline void set_pcb_dbregs(void)
{
    uint64_t p_pcb_flags = kpeek64(kpeek64((uint64_t)pcpu)+td_pcb) + pcb_flags;
    kpoke64(p_pcb_flags, kpeek64(p_pcb_flags) | PCB_DBREGS);
}
