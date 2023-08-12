#include <errno.h>
#include <string.h>
#include "utils.h"
#include "log.h"
#include "structs.h"
#include "traps.h"

int virt2phys(uint64_t addr, uint64_t* phys, uint64_t* phys_limit)
{
    uint64_t pml = cr3_phys;
    for(int i = 39; i >= 12; i -= 9)
    {
        if(pml >= ((1ull << 39) - (1ull << 12))) //dmem mapping size
        {
            log_word(0xdead0000dead0000);
            return 0;
        }
        uint64_t next_pml = *(uint64_t*)(DMEM + pml + ((addr & (0x1ffull << i)) >> (i - 3)));
        if(!(next_pml & 1))
        {
            log_word(0xdeaddeaddeaddead);
            return 0;
        }
        if((next_pml & 128) || i == 12)
        {
            uint64_t addr1 = next_pml & ((1ull << 52) - (1ull << i));
            addr1 |= addr & ((1ull << i) - 1);
            *phys = addr1;
            *phys_limit = (addr1 | ((1ull << i) - 1)) + 1;
            return 1;
        }
        pml = next_pml & ((1ull << 52) - (1ull << 12));
    }
}

int copy_from_kernel(void* dst, uint64_t src, uint64_t sz)
{
    char* p_dst = dst;
    uint64_t phys, phys_end;
    while(sz)
    {
        if(!virt2phys(src, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(p_dst, DMEM+phys, chk);
        p_dst += chk;
        src += chk;
        sz -= chk;
    }
    return 0;
}

int copy_to_kernel(uint64_t dst, const void* src, uint64_t sz)
{
    const char* p_src = src;
    uint64_t phys, phys_end;
    while(sz)
    {
        if(!virt2phys(dst, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(DMEM+phys, p_src, chk);
        dst += chk;
        p_src += chk;
        sz -= chk;
    }
    return 0;
}

void yield(void);
void unyield(uint64_t rsp);

void run_gadget(uint64_t* regs)
{
    copy_to_kernel(trap_frame, regs, NREGS*8);
    yield();
    copy_from_kernel(regs, trap_frame, NREGS*8);
}

extern char dr2gpr_start[];
extern char gpr2dr_1_start[];
extern char gpr2dr_2_start[];
extern char rdmsr_start[];
extern char rdmsr_end[];
extern char doreti_iret[];
extern char syscall_after[];

void read_dbgregs(uint64_t* dr)
{
    uint64_t regs[NREGS] = { [RIP] = (uint64_t)dr2gpr_start, 0x20, 2, 0, 0, [R8] = 0xdeadbeefdeadbeef };
    run_gadget(regs);
    dr[0] = regs[R15];
    dr[1] = regs[R14];
    dr[2] = regs[R13];
    dr[3] = regs[R12];
    dr[4] = regs[R11];
    dr[5] = regs[RAX];
}

void write_dbgregs(const uint64_t* dr)
{
    uint64_t regs[NREGS] = { [RIP] = (uint64_t)gpr2dr_1_start, 0x20, 2, 0, 0, [R8] = 0xdeadbeefdeadbeef };
    regs[R15] = dr[0];
    regs[R14] = dr[1];
    regs[R13] = dr[2];
    regs[RBX] = dr[3];
    regs[R11] = dr[4];
    regs[RCX] = dr[5];
    regs[RAX] = dr[5];
    run_gadget(regs);
    regs[R11] = dr[4];
    regs[R15] = dr[5];
    regs[R12] = 0xdeadbeefdeadbeef;
    regs[RIP] = (uint64_t)gpr2dr_2_start;
    run_gadget(regs);
}

int rdmsr(uint32_t which, uint64_t* ans)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)rdmsr_start, 0x20, 0x102, 0, 0,
        [RCX] = which,
    };
    run_gadget(regs);
    if(regs[RIP] == (uint64_t)rdmsr_start)
        return 0;
    *ans = regs[RDX] << 32 | (uint32_t)regs[RAX];
    return 1;
}

void start_syscall_with_dbgregs(uint64_t* regs, const uint64_t* dbgregs)
{
    regs[RSI] = regs[RSP] + syscall_rsp_to_rsi;
    uint64_t stack_frame[13] = {
        (uint64_t)doreti_iret,
        MKTRAP(TRAP_UTILS, 1), 0, 0, 0, 0,
    };
    read_dbgregs(stack_frame+6);
    push_stack(regs, stack_frame, sizeof(stack_frame));
    set_pcb_dbregs();
    write_dbgregs(dbgregs);
    regs[RIP] = kpeek64(regs[RAX] + 8);
}

void handle_utils_trap(uint64_t* regs, uint32_t trapno)
{
    if(trapno == 1)
    {
        uint64_t stack_frame[12];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        write_dbgregs(stack_frame+5);
        regs[RIP] = (uint64_t)syscall_after;
    }
}
