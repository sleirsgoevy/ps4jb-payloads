#include "offsets.h"

struct offset_table offsets;
extern uint64_t kdata_base;

#define OFFSET(x) offsets.x = kdata_base + x;
#define DEF(x, y) enum { x = (y) + 0 * sizeof(offsets.x) };

#define START_FW(fw) void set_offsets_ ## fw(void) {
#define END_FW() }

START_FW(403)
DEF(allproc, 0x27edcb8)
DEF(idt, 0x64cdc80)
DEF(gdt_array, 0x64cee30)
DEF(tss_array, 0x64d0830)
DEF(pcpu_array, 0x64d2280)
DEF(doreti_iret, -0x9cf84c)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x99002a /*-0x990a55*/)
DEF(rdmsr_start, -0x9d0cfa /*-0x9d6d02*/)
//DEF(rdmsr_end, -0x9d6cf9)
DEF(wrmsr_ret, -0x9d20cc)
DEF(dr2gpr_start, -0x9d6d93)
//DEF(dr2gpr_end, -0x9d6d7c)
DEF(gpr2dr_1_start, -0x9d6c7a)
//DEF(gpr2dr_1_end, -0x9d6c55)
DEF(gpr2dr_2_start, -0x9d6b87)
//DEF(gpr2dr_2_end, -0x9d6de9)
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
DEF(sysents_ps4, 0x168410)
DEF(sysentvec, 0xd11bb8)
DEF(sysentvec_ps4, 0xd11d30)
DEF(sceSblServiceMailbox, -0x6824c0)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8a5c40)
DEF(mdbg_call_fix, -0x631ea9)
DEF(syscall_before, -0x802311)
DEF(syscall_after, -0x8022ee)
DEF(malloc, -0xa9b00)
DEF(M_something, 0x1346080)
DEF(loadSelfSegment_epilogue, -0x8a54cd)
DEF(loadSelfSegment_watchpoint, -0x2cc918)
DEF(loadSelfSegment_watchpoint_lr, -0x8a5727)
DEF(decryptSelfBlock_watchpoint, -0x2cc88e)
DEF(decryptSelfBlock_watchpoint_lr, -0x8a538a)
DEF(decryptSelfBlock_epilogue, -0x8a52c3)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8a4c55)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8a47d2)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8a58bc)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8a5541)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8a5014)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8a488c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8a5cbe)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x94a7f0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x94ada4)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x94ad2e)
DEF(sceSblPfsSetKeys, -0x94aaa0)
DEF(panic, -0x21020)
DEF(sceSblServiceCryptAsync, -0x8ed940)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8ed902)
DEF(copyin, -0x9908e0)
DEF(copyout, -0x990990)
DEF(crypt_message_resolve, -0x479d60)
DEF(justreturn, -0x9cf990)
DEF(justreturn_pop, justreturn+8)
DEF(mini_syscore_header, 0xdc16e8)
DEF(pop_all_iret, -0x9cf8ab)
DEF(pop_all_except_rdi_iret, pop_all_iret+4)
DEF(push_pop_all_iret, -0x96be70)
DEF(kernel_pmap_store, 0x3257a78)
DEF(crypt_singleton_array, 0x2e31830)
DEF(security_flags, 0x6506474)
DEF(targetid, 0x650647d)
DEF(qa_flags, 0x6506498)
DEF(utoken, 0x6506500)
#include "offset_list.txt"
END_FW()

START_FW(450)
DEF(allproc, 0x27edcb8) // ok
DEF(idt, 0x64cdc80) // ok
DEF(gdt_array, 0x64cee30) // ok
DEF(tss_array, 0x64d0830) // ok
DEF(pcpu_array, 0x64d2280) // ok
DEF(doreti_iret, -0x9cf84c) // ok
DEF(add_rsp_iret, doreti_iret - 7) // ok
DEF(swapgs_add_rsp_iret, doreti_iret - 10) // ok
DEF(rep_movsb_pop_rbp_ret, -0x99002a /*-0x990a55*/) // ok
DEF(rdmsr_start, -0x9d0cfa /*-0x9d6d02*/) // ok
//DEF(rdmsr_end, -0x9d6cf9) // ok
DEF(wrmsr_ret, -0x9d20cc) // ok
DEF(dr2gpr_start, -0x9d6d93) // ok
//DEF(dr2gpr_end, -0x9d6d7c) // ok
DEF(gpr2dr_1_start, -0x9d6c7a) // ok
//DEF(gpr2dr_1_end, -0x9d6c55) // ok
DEF(gpr2dr_2_start, -0x9d6b87) // ok
//DEF(gpr2dr_2_end, -0x9d6de9) // ok
DEF(mov_cr3_rax, -0x396e4e) // ok?, fixed
DEF(mov_rdi_cr3, -0x396ebe) // ok, fixed
DEF(nop_ret, -0x396de1) // ok, fixed, got from pmap_activate_sw
DEF(cpu_switch, -0x9d6f80) // ok
DEF(mprotect_fix_start, -0x90ac61) // ok
DEF(mprotect_fix_end, mprotect_fix_start+6) // ok
DEF(mmap_self_fix_1_start, -0x2cd16d) // ok, fixed
DEF(mmap_self_fix_1_end, mmap_self_fix_1_start+2) // ok
DEF(mmap_self_fix_2_start, -0x1df11e) // ok, fixed
DEF(mmap_self_fix_2_end, mmap_self_fix_2_start+2) // ok
DEF(sigaction_fix_start, -0x6c2989)
DEF(sigaction_fix_end, -0x6c2933)
DEF(sysents, 0x1709c0) // ok
DEF(sysents_ps4, 0x168410) // ok
DEF(sysentvec, 0xd11bb8) // ok
DEF(sysentvec_ps4, 0xd11d30) // ok
DEF(sceSblServiceMailbox, -0x6824c0)
DEF(sceSblAuthMgrSmIsLoadable2, -0x8a5c40)
DEF(mdbg_call_fix, -0x631ea9)
DEF(syscall_before, -0x802311)
DEF(syscall_after, -0x8022ee)
DEF(malloc, -0xa9b00)
DEF(M_something, 0x1346080) // ok
DEF(loadSelfSegment_epilogue, -0x8a54cd)
DEF(loadSelfSegment_watchpoint, -0x2cc918)
DEF(loadSelfSegment_watchpoint_lr, -0x8a5727)
DEF(decryptSelfBlock_watchpoint, -0x2cc88e)
DEF(decryptSelfBlock_watchpoint_lr, -0x8a538a)
DEF(decryptSelfBlock_epilogue, -0x8a52c3)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x8a4c55)
DEF(decryptMultipleSelfBlocks_epilogue, -0x8a47d2)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x8a58bc)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8a5541)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8a5014)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x8a488c)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x8a5cbe)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x94a7f0)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x94ada4)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x94ad2e)
DEF(sceSblPfsSetKeys, -0x94aaa0)
DEF(panic, -0x21020)
DEF(sceSblServiceCryptAsync, -0x8ed940)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x8ed902)
DEF(copyin, -0x9908e0)
DEF(copyout, -0x990990)
DEF(crypt_message_resolve, -0x479d60)
DEF(justreturn, -0x9cf990) // ok
DEF(justreturn_pop, justreturn+8) // ok
DEF(mini_syscore_header, 0xdc16e8) // ok
DEF(pop_all_iret, -0x9cf8ab) // ok
DEF(pop_all_except_rdi_iret, pop_all_iret+4) // ok
DEF(push_pop_all_iret, -0x96db88) // ok, fixed
DEF(kernel_pmap_store, 0x3257a78) // ok
DEF(crypt_singleton_array, 0x2e31830) // ok
DEF(security_flags, 0x6506474) // ok
DEF(targetid, 0x650647d) // ok
DEF(qa_flags, 0x6506498) // ok
DEF(utoken, 0x6506500) // ok
#include "offset_list.txt"
END_FW()

void* dlsym(void*, const char*);

int set_offsets(void)
{
    int(*sceKernelGetProsperoSystemSwVersion)(uint32_t*) = dlsym((void*)0x2001, "sceKernelGetProsperoSystemSwVersion");
    uint32_t buf[10];
    sceKernelGetProsperoSystemSwVersion(buf);
    uint32_t ver = buf[9] >> 16;
    switch(ver)
    {
#ifndef NO_BUILTIN_OFFSETS
    case 0x403: set_offsets_403(); break;
    case 0x450: set_offsets_450(); break;
#endif
    default: return -1;
    }
    return 0;
}
