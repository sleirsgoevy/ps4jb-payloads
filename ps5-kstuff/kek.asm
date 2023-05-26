use64

extern syscall_before
extern sysents
extern syscall_after
extern rep_movsb_pop_rbp_ret
extern doreti_iret
extern push_pop_all_iret
extern pop_all_iret
extern pop_all_except_rdi_iret
extern add_rsp_iret
extern dr2gpr_start
extern dr2gpr_end
extern gpr2dr_1_start
extern gpr2dr_1_end
extern gpr2dr_2_start
extern gpr2dr_2_end
extern scratchpad
extern copyin
extern copyout

%include "structs.inc"

global _start

_start:
; fake 16-byte header for the loader
dq add_rsp_iret
dq iret_stack

align 16
iret_errc:
dq 0 ; error code pushed by cpu
iret_frame:
times 5 dq 0
iret_stack:
times (iret_rip-(iret_stack-iret_errc)) db 0
dq push_pop_all_iret
dq 0x20
dq 2
dq regs_stash_exit
dq 0

; reserve some space for the push gadget's stack
times 128 db 0

regs_stash:
times iret_rip db 0
regs_stash_exit:
dq pop_all_iret
dq 0x20
dq 2
dq prog_entry
dq 0

regs_for_exit:
times iret_ss+8 db 0

; memcpy0f dest, src, size, retaddr, flags
%macro memcpy0f 5
; assuming that rdi/rsi/rdx/rcx are the first 4 registers
dq (%1)
dq (%2)
dq 0
dq (%3)
times (iret_rip-32) db 0
; iret frame
dq rep_movsb_pop_rbp_ret
dq 0x20
dq (%5)
dq %%target
dq 0
%%target:
dq 0 ; rbp
dq (%4) ; return address
%endmacro

; memcpy0 dest, src, size, retaddr
%macro memcpy0 4
memcpy0f (%1), (%2), (%3), (%4), 2
%endmacro

; rmemcpy0 dest, src, size, retaddr
%macro rmemcpy0 4
memcpy0f (%1), (%2), (%3), (%4), 0x402
%endmacro

; memcpy dest, src, size
%macro memcpy 3
memcpy0 (%1), (%2), (%3), pop_all_iret
%endmacro

; rmemcpy dest, src, size
%macro rmemcpy 3
rmemcpy0 (%1), (%2), (%3), pop_all_iret
%endmacro

; memcat dest, src, size
%macro memcat 3
memcpy0 (%1), (%2), (%3), pop_all_except_rdi_iret
%endmacro

; rmemcat dest, src, size
%macro rmemcat 3
rmemcpy0 (%1), (%2), (%3), pop_all_except_rdi_iret
%endmacro

; pokeq0 dest, value, retaddr
%macro pokeq0 3
memcpy0 (%1), %%value, 8, (%3)
section .data.qword
%%value:
dq (%2)
section .text
%endmacro

; pokeq dest, value
%macro pokeq 2
memcpy (%1), %%value, 8
section .data.qword
%%value:
dq (%2)
section .text
%endmacro

; ptr_add_imm p_dest, p_ptr, imm
%macro ptr_add_imm 3
memcpy %%seek+iret_rsi, (%2), 8
%%seek:
memcpy0 scratchpad, 0, (%3), doreti_iret
save_reg (%1), iret_rsi
%endmacro

; memcpy_offset p_dest, offset, src, size
%macro memcpy_offset 4
ptr_add_imm %%poke+iret_rdi, (%1), (%2)
%%poke:
memcpy 0, (%3), (%4)
%endmacro

; memcpy_from_offset dest, p_src, offset, size
%macro memcpy_from_offset 4
ptr_add_imm %%peek+iret_rsi, (%2), (%3)
%%peek:
memcpy (%1), 0, (%4)
%endmacro

; cmpb ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpb 5
memcpy %%poke1+iret_rsi+1, (%1), 1
memcpy %%poke1+iret_rsi, (%2), 1
%%poke1:
memcpy %%poke2+iret_rsi, comparison_table, 1
%%poke2:
memcpy0 %%iret+24, %%jump_table, 8, doreti_iret
%%iret:
dq pop_all_iret
dq 0x20
dq 2
dq 0
dq 0
section .data.qword
align 256
%%jump_table:
dq (%3)
dq (%4)
dq (%5)
section .text
%endmacro

; cmpw ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpw 5
cmpb (%1)+1, (%2)+1, (%3), %%next_check, (%5)
%%next_check:
cmpb (%1), (%2), (%3), (%4), (%5)
%endmacro

; cmpwbe ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpwbe 5
cmpb (%1), (%2), (%3), %%next_check, (%5)
%%next_check:
cmpb (%1)+1, (%2)+1, (%3), (%4), (%5)
%endmacro

; cmpd ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpd 5
cmpw (%1)+2, (%2)+2, (%3), %%next_check, (%5)
%%next_check:
cmpw (%1), (%2), (%3), (%4), (%5)
%endmacro

; cmpdbe ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpdbe 5
cmpwbe (%1), (%2), (%3), %%next_check, (%5)
%%next_check:
cmpwbe (%1)+2, (%2)+2, (%3), (%4), (%5)
%endmacro

; cmpq ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpq 5
cmpd (%1)+4, (%2)+4, (%3), %%next_check, (%5)
%%next_check:
cmpd (%1), (%2), (%3), (%4), (%5)
%endmacro

; cmpqbe ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpqbe 5
cmpdbe (%1), (%2), (%3), %%next_check, (%5)
%%next_check:
cmpdbe (%1)+4, (%2)+4, (%3), (%4), (%5)
%endmacro

; cmpdi ptr1, imm, is_less, is_equal, is_greater
%macro cmpdi 5
cmpd (%1), %%value, (%3), (%4), (%5)
section .data.dword
%%value:
dd (%2)
section .text
%endmacro

; cmpdibe ptr1, imm, is_less, is_equal, is_greater
%macro cmpdibe 5
cmpdbe (%1), %%value, (%3), (%4), (%5)
section .data.dword
%%value:
dd (%2)
section .text
%endmacro

; cmpqi ptr1, imm, is_less, is_equal, is_greater
%macro cmpqi 5
cmpq (%1), %%value, (%3), (%4), (%5)
section .data.qword
%%value:
dq (%2)
section .text
%endmacro

; cmpqibe ptr1, imm, is_less, is_equal, is_greater
%macro cmpqibe 5
cmpqbe (%1), %%value, (%3), (%4), (%5)
section .data.qword
%%value:
dq (%2)
section .text
%endmacro

; orb ptr1, ptr2
%macro orb 2
memcpy %%peek+iret_rsi, (%1), 1
memcpy %%peek+iret_rsi+1, (%2), 1
%%peek:
memcpy (%1), or_table, 1
%endmacro

; orbi ptr1, imm
%macro orbi 2
memcpy %%peek+iret_rsi+1, (%1), 1
%%peek:
memcpy (%1), or_table+(%2), 1
%endmacro

; save_reg where, what
%macro save_reg 2
dq push_pop_all_iret
dq 0x20
dq 2
dq %%regs_stash_exit
dq 0
times 128 db 0
%%regs_stash:
times iret_rip db 0
%%regs_stash_exit:
dq pop_all_iret
dq 0x20
dq 2
dq %%after_regs_stash
dq 0
%%after_regs_stash:
memcpy (%1), %%regs_stash+(%2), 8
%endmacro

; log_word which
%macro log_word 1
cmpq log_area_cur, log_area_end, %%write, %%skip, %%write
%%write:
memcpy log_staging, iret_frame, 8
memcpy log_staging+8, (%1), 8
memcpy %%poke+iret_rdi, log_area_cur, 8
%%poke:
memcpy0 0, log_staging, 16, doreti_iret
save_reg log_area_cur, iret_rdi
%%skip:
%endmacro

; replace_word ptr1, value1, value2
%macro replace_word 3
%%start:
cmpw (%1), %%value1, %%skip, %%change, %%skip
%%change:
memcpy (%1), %%value2, 2
%%skip:
section .data.word
%%value1:
dw (%2)
%%value2:
dw (%3)
section .text
%endmacro

; replace_word_log ptr1, value1, value2, token
%macro replace_word_log 4
%%start:
cmpw (%1), %%value1, %%skip, %%change, %%skip
%%change:
log_word %%token
memcpy (%1), %%value2, 2
%%skip:
section .data.word
%%value1:
dw (%2)
%%value2:
dw (%3)
section .data.qword
%%token:
dq (%4)
section .text
%endmacro

; decrypt_pointer ptr1
%macro decrypt_pointer 1
replace_word (%1)+6, 0xdeb7, 0xffff
%endmacro

; decrypt_pointer_log ptr1, token
%macro decrypt_pointer_log 2
replace_word_log (%1)+6, 0xdeb7, 0xffff, (%2)
%endmacro

; encrypt_pointer ptr1
%macro encrypt_pointer 1
replace_word (%1)+6, 0xffff, 0xdeb7
%endmacro

; decrypt_one label, which
%macro decrypt_one 2
%1:
decrypt_pointer regs_stash+(%2)
times iret_rip db 0
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0
%endmacro

; if_equal cond, arg1, arg2, then
%macro if_equal 4
%1 (%2), (%3), %%next_check, (%4), %%next_check
%%next_check:
%endmacro

; if_not_equal cond, arg1, arg2, then
%macro if_not_equal 4
%1 (%2), (%3), (%4), %%next_check, (%4)
%%next_check:
%endmacro

; on_rip rip, tgt
%macro on_rip 2
;cmpqibe iret_frame, (%1), %%next_check, (%2), %%next_check
;%%next_check:
if_equal cmpqibe, iret_frame, (%1), (%2)
%endmacro

; push_stack start, length
%macro push_stack 2
memcpy %%peek+iret_rsi, iret_frame+24, 8
memcpy %%poke+iret_rdi, iret_frame+24, 8
%%peek:
memcpy %%stash, 0, 1
%%poke:
rmemcat 0, %%stash, 1
rmemcat 0, (%1)+(%2)-1, (%2)
memcpy0 0, %%stash, 1, doreti_iret
save_reg iret_frame+24, iret_rdi
section .data.byte
%%stash:
db 0
section .text
%endmacro

; pop_stack start, length
%macro pop_stack 2
memcpy %%peek+iret_rsi, iret_frame+24, 8
%%peek:
memcpy0 (%1), 0, (%2), doreti_iret
save_reg iret_frame+24, iret_rsi
%endmacro

; pushqi imm
%macro pushqi 1
push_stack %%value, 8
section .data.qword
%%value:
dq (%1)
section .text
%endmacro

; read_dbgregs
%macro read_dbgregs 0
pokeq0 read_dbgregs_lr, %%end_macro, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq read_dbgregs_fn
dq 0
%%end_macro:
%endmacro

%macro write_dbgregs 0
pokeq0 write_dbgregs_lr, %%end_macro, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq write_dbgregs_fn
dq 0
%%end_macro:
%endmacro

prog_entry:

%include "parasites.inc"

; actual logic starts here

on_rip syscall_before, handle_syscall_before
on_rip doreti_iret, handle_broken_iret
on_rip dr2gpr_end, read_dbgregs_ret
on_rip gpr2dr_1_end, write_dbgregs_ret1
on_rip gpr2dr_2_end, write_dbgregs_ret2

on_rip 0xde00ad0000000001, handle_kekcall_write_dbregs_after_copyout

; generic fallback for unknown crashes

decrypt_pointer_log regs_stash+iret_rax, 0
decrypt_pointer_log regs_stash+iret_rcx, 1
decrypt_pointer_log regs_stash+iret_rdx, 2
decrypt_pointer_log regs_stash+iret_rbx, 3
decrypt_pointer_log regs_stash+iret_rbp, 5
decrypt_pointer_log regs_stash+iret_rsi, 6
decrypt_pointer_log regs_stash+iret_rdi, 7
decrypt_pointer_log regs_stash+iret_r8, 8
decrypt_pointer_log regs_stash+iret_r9, 9
decrypt_pointer_log regs_stash+iret_r10, 10
decrypt_pointer_log regs_stash+iret_r11, 11
decrypt_pointer_log regs_stash+iret_r12, 12
decrypt_pointer_log regs_stash+iret_r13, 13
decrypt_pointer_log regs_stash+iret_r14, 14
decrypt_pointer_log regs_stash+iret_r15, 15

decrypt_end:
memcpy regs_for_exit, regs_stash, iret_rip
memcpy0 regs_for_exit+iret_rip, iret_frame, 40, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq regs_for_exit
dq 0

handle_broken_iret:
; just pretend that we crashed inside the iret
memcpy .copy+iret_rsi, iret_frame+24, 8
.copy:
memcpy0 iret_frame, 0, 40, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq prog_entry
dq 0

handle_syscall_before:
decrypt_pointer regs_stash+iret_rax
cmpqibe regs_stash+iret_rax, sysents+48*39, decrypt_end, handle_getppid, decrypt_end

handle_getppid:
memcpy_from_offset regs_for_exit, iret_frame+24, syscall_rsp_to_regs_stash, iret_rip+40

; handle kekcalls
if_equal cmpdibe, regs_for_exit+iret_rax+4, 1, handle_kekcall_read_dbregs
if_equal cmpdibe, regs_for_exit+iret_rax+4, 2, handle_kekcall_write_dbregs

; call real getppid
pushqi syscall_after
memcpy0 iret_frame, sysents+48*39+8, 8, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

handle_kekcall_read_dbregs:
; set syscall return value to 0
memcpy_offset regs_stash+iret_rdi, td_retval, zero, 8
; rsi = destination, from userspace
memcpy regs_stash+iret_rsi, regs_for_exit+iret_rdi, 8
; rdx = count, fixed
pokeq regs_stash+iret_rdx, 48
; read debug registers
read_dbgregs
; prepare stack frame
memcpy dbgreg_copyout_frame_dbgregs, dbgregs, 48
memcpy dbgreg_copyout_frame_rsp, iret_frame+24, 8
; push debug registers to kernel stack
push_stack dbgreg_copyout_frame_dbgregs, dbgreg_copyout_frame_end-dbgreg_copyout_frame_dbgregs
; rdi = source, copy from kernel stack
memcpy regs_stash+iret_rdi, iret_frame+24, 8
; set return address
pokeq dbgreg_copyout_frame_rip, syscall_after
; push the rest of the stack frame
push_stack dbgreg_copyout_frame, dbgreg_copyout_frame_dbgregs-dbgreg_copyout_frame
; set rip
pokeq0 iret_frame, copyout, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

handle_kekcall_write_dbregs:
; set syscall return value to 0
memcpy_offset regs_stash+iret_rdi, td_retval, zero, 8
; save the thread pointer into the spare 7th slot
memcpy dbgreg_copyout_frame_dbgregs+48, regs_stash+iret_rdi, 8
; rdi = source, from userspace
memcpy regs_stash+iret_rdi, regs_for_exit+iret_rdi, 8
; rdx = count, fixed
pokeq regs_stash+iret_rdx, 48
; allocate space for debug registers on kernel stack
push_stack dbgreg_copyout_frame_dbgregs, dbgreg_copyout_frame_end-dbgreg_copyout_frame_dbgregs
; iret should not pop this data
memcpy dbgreg_copyout_frame_rsp, iret_frame+24, 8
; rsi = destination, copy to kernel stack
memcpy regs_stash+iret_rsi, iret_frame+24, 8
; set up magic return
pokeq dbgreg_copyout_frame_rip, 0xde00ad0000000001
; push the rest of the stack frame
push_stack dbgreg_copyout_frame, dbgreg_copyout_frame_dbgregs-dbgreg_copyout_frame
; set rip
pokeq0 iret_frame, copyin, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

handle_kekcall_write_dbregs_after_copyout:
; pop the data from stack
pop_stack dbgreg_copyout_frame_dbgregs, dbgreg_copyout_frame_end-dbgreg_copyout_frame_dbgregs
; check if copyin has succeeded
if_not_equal cmpdibe, regs_stash+iret_rax, 0, .copyin_failed
; write debug registers
memcpy dbgregs, dbgreg_copyout_frame_dbgregs, 48
write_dbgregs
; get td_pcb
memcpy_from_offset dbgreg_copyout_frame_dbgregs+48, dbgreg_copyout_frame_dbgregs+48, td_pcb, 8
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
; done, now return
.copyin_failed:
pokeq0 iret_frame, syscall_after, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

;pokeq iret_frame, syscall_after
;push_stack iret_frame, 40
;pokeq iret_frame, doreti_iret
;read_dbgregs
;memcpy_offset regs_stash+iret_rdi, td_retval, dbgregs+32, 8
;pokeq0 regs_stash+iret_rax, 0, doreti_iret
;dq pop_all_iret
;dq 0x20
;dq 2
;dq decrypt_end
;dq 0

; simple decrypts
decrypt_one decrypt_rax_only, iret_rax
decrypt_one decrypt_rcx_only, iret_rcx
decrypt_one decrypt_rdx_only, iret_rdx
decrypt_one decrypt_rbx_only, iret_rbx
decrypt_one decrypt_rbp_only, iret_rbp
decrypt_one decrypt_rsi_only, iret_rsi
decrypt_one decrypt_rdi_only, iret_rdi
decrypt_one decrypt_r8_only, iret_r8
decrypt_one decrypt_r9_only, iret_r9
decrypt_one decrypt_r10_only, iret_r10
decrypt_one decrypt_r11_only, iret_r11
decrypt_one decrypt_r12_only, iret_r12
decrypt_one decrypt_r13_only, iret_r13
decrypt_one decrypt_r14_only, iret_r14
decrypt_one decrypt_r15_only, iret_r15

read_dbgregs_fn:
memcpy regs_for_exit, regs_stash, iret_rip
memcpy regs_for_exit+iret_rip, iret_frame, 40
times iret_r8 db 0
dq 0xdeadbeefdeadbeef
times (iret_rip-iret_r8-8) db 0
dq dr2gpr_start
dq 0x20
dq 2
dq 0
dq 0
read_dbgregs_ret:
memcpy dbgregs, regs_stash+iret_r15, 8
memcpy dbgregs+8, regs_stash+iret_r14, 8
memcpy dbgregs+16, regs_stash+iret_r13, 8
memcpy dbgregs+24, regs_stash+iret_r12, 8
memcpy dbgregs+32, regs_stash+iret_r11, 8
memcpy dbgregs+40, regs_stash+iret_rax, 8
memcpy regs_stash, regs_for_exit, iret_rip
memcpy0 iret_frame, regs_for_exit+iret_rip, 40, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
read_dbgregs_lr:
dq 0
dq 0

write_dbgregs_fn:
memcpy .run_gadget1+iret_r15, dbgregs, 8
memcpy .run_gadget1+iret_r14, dbgregs+8, 8
memcpy .run_gadget1+iret_r13, dbgregs+16, 8
memcpy .run_gadget1+iret_rbx, dbgregs+24, 8
memcpy .run_gadget1+iret_r11, dbgregs+32, 8
memcpy .run_gadget1+iret_rcx, dbgregs+40, 8
memcpy .run_gadget1+iret_rax, dbgregs+40, 8
memcpy regs_for_exit, regs_stash, iret_rip
memcpy regs_for_exit+iret_rip, iret_frame, 40
.run_gadget1:
times iret_r8 db 0
dq 0xdeadbeefdeadbeef
times (iret_rip-iret_r8-8) db 0
dq gpr2dr_1_start
dq 0x20
dq 2
dq 0
dq 0
write_dbgregs_ret1:
memcpy .run_gadget2+iret_r11, dbgregs+32, 8
memcpy .run_gadget2+iret_r15, dbgregs+40, 8
.run_gadget2:
times iret_r12 db 0
dq 0xdeadbeefdeadbeef
times (iret_rip-iret_r12-8) db 0
dq gpr2dr_2_start
dq 0x20
dq 2
dq 0
dq 0
write_dbgregs_ret2:
memcpy regs_stash, regs_for_exit, iret_rip
memcpy0 iret_frame, regs_for_exit+iret_rip, 40, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
write_dbgregs_lr:
dq 0
dq 0

section .data.qword

dbgregs:
times 6 dq 0

dbgreg_copyout_frame:
dq doreti_iret
dbgreg_copyout_frame_rip:
dq 0
dq 0x20
dq 0x202
dbgreg_copyout_frame_rsp:
dq 0
zero:
dq 0
dbgreg_copyout_frame_dbgregs:
times 7 dq 0
dbgreg_copyout_frame_end:

; pseudocode:
; comparison_table[a][b] = 8 * (intcmp(a, b) + 1)
section .data.align16
align 65536
comparison_table:
%rep 65536
db ((($-comparison_table)/256 - ($-comparison_table) % 256 + 256) / 256 + (($-comparison_table)/256 - ($-comparison_table) % 256 + 255) / 256) * 8
%endrep

; pseudocode:
; or_table[a][b] = a | b
section .data.align16
align 65536
or_table:
%rep 65536
db (($-or_table)/256) | (($-or_table) % 256)
%endrep

section .data.log
log_staging:
dq 0
dq 0
log_area:
times 4096 db 0
log_area_end:
dq log_area_end
log_area_cur:
dq log_area
