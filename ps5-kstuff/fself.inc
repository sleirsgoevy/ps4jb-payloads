extern decryptSelfBlock_epilogue
extern decryptSelfBlock_watchpoint_lr
extern loadSelfSegment_epilogue
extern loadSelfSegment_watchpoint_lr
extern mini_syscore_header
extern sceSblSerivceIsLoadable2
extern sceSblServiceMailbox
extern sceSblServiceMailbox_lr_decryptSelfBlock
extern sceSblServiceMailbox_lr_loadSelfSegment
extern sceSblServiceMailbox_lr_verifyHeader

do_load_self_paid:
memcpy file_header, 0, 64
decrypt_pointer file_header+56
memcpy .copy2+iret_rsi, file_header+56, 8
memcpy .seek1+iret_rsi, file_header+56, 8
memcpy .seek2+iret_rsi, file_header+56, 8
.copy2:
memcpy file_header, 0, 32
memcpy file_header+26, zero, 6
mulq32 .seek1+iret_rcx, file_header+24
.seek1:
memcpy0 scratchpad, 0, 0, doreti_iret
save_reg .copy3+iret_rsi, iret_rsi
memcpy .seek2+iret_rsi, .copy3+iret_rsi, 8
.copy3:
memcpy file_header, 0, 96
memcpy file_header+32+58, zero, 6
mulq56 file_header+32+56, file_header+32+56
addq file_header+32+32, file_header+32+32, file_header+32+56
addq .seek2+iret_rcx, file_header+32+32, num47
andbi .seek2+iret_rcx, 0xf0
.seek2:
memcpy0 scratchpad, 0, 0, doreti_iret
save_reg .copy4+iret_rsi, iret_rsi
.copy4:
memcpy0 file_header, 0, 16, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
load_self_paid_lr:
dq 0
dq 0
num47:
dq 47

; load_self_paid p_ctx
%macro load_self_paid 1
memcpy do_load_self_paid+iret_rsi, (%1), 8
pokeq0 load_self_paid_lr, %%end_macro, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq do_load_self_paid
dq 0
%%end_macro:
%endmacro

handle_dynlib_load_prx:
; fix up rsi for the original syscall
ptr_add_imm regs_stash+iret_rsi, iret_frame+24, syscall_rsp_to_rsi
; read and save current debug registers
read_dbgregs
memcpy dbgreg_copyout_frame_dbgregs, dbgregs, 48
; set up a stack frame to restore them on return
pokeq dbgreg_copyout_frame_rip, 0xde00ad0000000002
; push old debug registers
push_stack dbgreg_copyout_frame_dbgregs, dbgreg_copyout_frame_end-dbgreg_copyout_frame_dbgregs
; save stack pointer, we don't want them popped
memcpy dbgreg_copyout_frame_rsp, iret_frame+24, 8
; push the rest of the stack frame
push_stack dbgreg_copyout_frame, dbgreg_copyout_frame_dbgregs-dbgreg_copyout_frame
; load modified debug registers
memcpy dbgregs, dbgregs_for_dynlib_load_prx, 48
write_dbgregs
; get td_pcb
memcpy_from_offset dbgreg_copyout_frame_dbgregs+48, regs_stash+iret_rdi, td_pcb, 8
; get pcb_flags pointer
ptr_add_imm .peek+iret_rsi, dbgreg_copyout_frame_dbgregs+48, pcb_flags
memcpy .poke+iret_rdi, .peek+iret_rsi, 8
; set PCB_DBREGS (2)
section .data.byte
.tmp:
db 0
section .text
.peek:
memcpy .tmp, 0, 1
orbi .tmp, 2
.poke:
memcpy 0, .tmp, 1
; call the original syscall
memcpy0 iret_frame, sysents+48*SYS_dynlib_load_prx+8, 8, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

dbgregs_for_dynlib_load_prx:
dq sceSblServiceMailbox
dq sceSblServiceIsLoadable2
dq 0
dq 0
dq 0
dq 0x405

handle_sceSblServiceMailbox:
memcpy .stack_peek+iret_rsi, iret_frame+24, 8
.stack_peek:
memcpy .lr, 0, 8
if_equal cmpqibe, .lr, sceSblServiceMailbox_lr_decryptSelfBlock, handle_sceSblServiceMailbox_decryptSelfBlock
if_equal cmpqibe, .lr, sceSblServiceMailbox_lr_loadSelfSegment, handle_sceSblServiceMailbox_loadSelfSegment
cmpqibe .lr, sceSblServiceMailbox_lr_verifyHeader, decrypt_end, handle_sceSblServiceMailbox_verifyHeader, decrypt_end
.lr:
dq 0

handle_sceSblServiceMailbox_verifyHeader:
load_self_paid regs_stash+iret_r14
if_not_equal cmpqibe, self_paid, 1, decrypt_end
memcpy .peek1+iret_rsi, regs_stash+iret_r14, 8
.peek1:
memcpy file_header, 0, 64
memcpy .peek2+iret_rsi, file_header+56, 8
memcpy .poke+iret_rdi, file_header+56, 8
.peek2:
memcpy fself_header_backup, 0, mini_syscore_header_size
push_stack fself_header_backup, fself_header_backup_end-fself_header_backup
memcpy fself_header_stack_push_cs, iret_frame+8, 32
push_stack fself_header_stack_push, fself_header_backup-fself_header_stack_push
memcpy_offset regs_stash+iret_rdx, 16, .mini_syscore_header_size, 4
.poke:
memcpy0 0, mini_syscore_header, mini_syscore_header_size, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0
.mini_syscore_header_size:
dq mini_syscore_header_size

handle_sceSblServiceMailbox_verifyHeader_return:
pop_stack fself_header_backup, fself_header_backup_end-fself_header_backup
pop_stack iret_frame, 8
memcpy .peek1+iret_rsi, regs_stash+iret_r14, 8
.peek1:
memcpy file_header, 0, 64
memcpy .poke+iret_rdi, file_header+56, 8
.poke:
memcpy0 0, fself_header_backup, mini_syscore_header_size, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

handle_sceSblServiceIsLoadable2:
load_self_paid regs_stash+iret_rdi
if_not_equal cmpqibe, self_paid, 1, decrypt_end
memcpy_offset regs_stash+iret_rdi, 0x3e, .death, 2
pop_stack iret_frame, 8
pokeq regs_stash+iret_rax, 0
memcpy .poke+iret_rdi, regs_stash+iret_r8, 8
.poke:
memcpy0 0, s_auth_info_for_dynlib, s_auth_info_for_dynlib_end-s_auth_info_for_dynlib, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0
.death:
dq 0xdeb7

handle_loadSelfSegment_parasite:
decrypt_pointer regs_stash+iret_r10
memcpy .peek+iret_rsi, iret_frame+24, 8
.peek:
memcpy parasite_push, 0, parasite_dbgregs-parasite_push
if_not_equal cmpqibe, parasite_lr, loadSelfSegment_watchpoint_lr, decrypt_end
pop_stack parasite_push, parasite_dbgregs-parasite_push
read_dbgregs
memcpy parasite_dbgregs, dbgregs, 48
memcpy dbgregs, dbgregs_for_loadSelfSegment, 48
write_dbgregs
push_stack parasite_push, parasite_push_end-parasite_push
times iret_rip db 0
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

dbgregs_for_loadSelfSegment:
dq sceSblServiceMailbox
dq loadSelfSegment_epilogue
dq 0
dq 0
dq 0
dq 0x405

handle_loadSelfSegment_return:
handle_decryptSelfBlock_return:
pop_stack dbgregs, 48
write_dbgregs
times iret_rip db 0
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

handle_sceSblServiceMailbox_loadSelfSegment:
load_self_paid regs_stash+iret_rbx
if_not_equal cmpqibe, self_paid, 1, decrypt_end
pop_stack iret_frame, 8
memcpy_offset regs_stash+iret_rdx, 4, zero, 4
memcpy0 regs_stash+iret_rax, zero, 8, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

handle_sceSblServiceMailbox_decryptSelfBlock:
memcpy_from_neg_offset .self_context, regs_stash+iret_rbp, sceSblServiceMailbox_decryptSelfBlock_rsp_to_rbp-sceSblServiceMailbox_decryptSelfBlock_rsp_to_self_context, 8
load_self_paid .self_context
if_not_equal cmpqibe, self_paid, 1, decrypt_end
memcpy_from_neg_offset .copy+iret_rdi, regs_stash+iret_rbp, sceSblServiceMailbox_decryptSelfBlock_rsp_to_rbp-sceSblServiceMailbox_decryptSelfBlock_rsp_to_target_va, 8
memcpy .peek+iret_rsi, regs_stash+iret_rdx, 8
.peek:
memcpy .request, 0, 56
subq .request, .copy+iret_rdi, .request+8
addq .copy+iret_rsi, .request, .request+16
memcpy .copy+iret_rcx, .request+48, 4
.copy:
memcpy 0, 0, 0
pop_stack iret_frame, 8
memcpy_offset regs_stash+iret_rdx, 4, zero, 4
memcpy0 regs_stash+iret_rax, zero, 8, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0
.self_context:
dq 0
.request:
times 7 dq 0

handle_decryptSelfBlock_parasite:
decrypt_pointer regs_stash+iret_rdx
memcpy .peek+iret_rsi, iret_frame+24, 8
.peek:
memcpy parasite_push, 0, parasite_dbgregs-parasite_push
if_not_equal cmpqibe, parasite_lr, decryptSelfBlock_watchpoint_lr, decrypt_end
read_dbgregs
memcpy parasite_dbgregs, dbgregs, 48
pop_stack parasite_push, parasite_dbgregs-parasite_push
push_stack parasite_push, parasite_push_end-parasite_push
memcpy dbgregs, dbgregs_for_decryptSelfBlock, 48
write_dbgregs
times iret_rip db 0
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

dbgregs_for_decryptSelfBlock:
dq sceSblServiceMailbox
dq decryptSelfBlock_epilogue
dq 0
dq 0
dq 0
dq 0x405

s_auth_info_for_dynlib:
dq 0x4900000000000002, 0x0, 0x800000000000ff00, 0x0, 0x0, 0x7000700080000000, 0x8000000000000000, 0x0, 0xf0000000ffff4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
s_auth_info_for_dynlib_end:

file_header:
times 8 db 0
self_paid:
times 120 db 0

align 16
fself_header_stack_push:
dq doreti_iret
dq 0xde01ad0000000001
fself_header_stack_push_cs:
dq 0x20
dq 0x202
dq 0
dq 0
fself_header_backup:
times mini_syscore_header_size db 0
align 16
fself_header_backup_end:
dq 0

parasite_push:
times 3 dq 0
parasite_lr:
dq 0
parasite_dbgregs:
times 6 dq 0
parasite_push_end:
