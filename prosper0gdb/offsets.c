#include "offsets.h"

struct offset_table offsets;
extern uint64_t kdata_base;

#define OFFSET(x) offsets.x = kdata_base + x;
#define DEF(x, y) x = (y) + 0 * sizeof(offsets.x),

#define START_FW(fw) void set_offsets_ ## fw(void) { enum {
#define MID_FW() };
#define END_FW() }

START_FW(403)
DEF(allproc, 0x27edcb8)
DEF(idt, 0x64cdc80)
DEF(gdt_array, 0x64cee30)
DEF(tss_array, 0x64d0830)
DEF(doreti_iret, -0x9cf84c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x990a55)
DEF(rdmsr_start, -0x9d6d02)
DEF(rdmsr_end, -0x9d6cf9)
DEF(wrmsr_ret, -0x9d20cc)
DEF(dr2gpr_start, -0x9d6d93)
DEF(dr2gpr_end, -0x9d6d7c)
DEF(gpr2dr_1_start, -0x9d6c7a)
DEF(gpr2dr_1_end, -0x9d6c55)
DEF(gpr2dr_2_start, -0x9d6b87)
DEF(gpr2dr_2_end, -0x9d6de9)
DEF(mov_cr3_rax, -0x396f9e)
DEF(mov_rdi_cr3, -0x39700e)
DEF(nop_ret, -0x28a3a0)
DEF(cpu_switch, -0x9d6f80)
DEF(mprotect_fix_start, -0x90ac61)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(mmap_self_fix_1_start, -0x2cd31d)
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2)
DEF(mmap_self_fix_2_start, -0x1df2ce)
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2)
DEF(sigaction_fix_start, -0x6c2989)
DEF(sigaction_fix_end, -0x6c2933)
DEF(sysents, 0x1709c0)
DEF(sceSblServiceMailbox, -0x6824c0)
DEF(sceSblAuthMgrIsLoadable2, -0x8a5c40)
DEF(mdbg_call_fix, -0x631ea9)
DEF(syscall_before, -0x802311)
DEF(syscall_after, -0x8022ee)
DEF(malloc, -0xa9b00)
DEF(M_something, 0x1346080)
DEF(loadSelfSegment_watchpoint, -0x2cc918)
DEF(loadSelfSegment_watchpoint_lr, -0x8a5727)
DEF(decryptSelfBlock_watchpoint, -0x2cc88e)
DEF(decryptSelfBlock_watchpoint_lr, -0x8a538a)
DEF(decryptSelfBlock_epilogue, -0x8a52c3)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8a58bc)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8a5541)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8a5014)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8a488c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8a5cbe)
DEF(sceSblPfsSetKeys, -0x94aaa0)
DEF(panic, -0x21020)
DEF(sceSblServiceCryptAsync, -0x8ed940)
MID_FW()
#include "offset_list.txt"
END_FW()

void* dlsym(void*, const char*);

void set_offsets(void)
{
    int(*sceKernelGetProsperoSystemSwVersion)(uint32_t*) = dlsym((void*)0x2001, "sceKernelGetProsperoSystemSwVersion");
    uint32_t buf[10];
    sceKernelGetProsperoSystemSwVersion(buf);
    uint32_t ver = buf[9] >> 16;
    switch(ver)
    {
    case 0x403: set_offsets_403(); break;
    }
}
