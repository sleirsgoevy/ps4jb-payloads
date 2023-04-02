use64

extern syscall_before
extern sysents
extern syscall_after
extern rep_movsb_pop_rbp_ret
extern doreti_iret
extern pop_all_iret
extern push_pop_all_iret
extern add_rsp_iret

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

; memcpy0 dest, src, size, retaddr
%macro memcpy0 4
; assuming that rdi/rsi/rdx/rcx are the first 4 registers
dq (%1)
dq (%2)
dq 0
dq (%3)
times (iret_rip-32) db 0
; iret frame
dq rep_movsb_pop_rbp_ret
dq 0x20
dq 2
dq %%target
dq 0
%%target:
dq 0 ; rbp
dq (%4) ; return address
%endmacro

; memcpy dest, src, size
%macro memcpy 3
memcpy0 (%1), (%2), (%3), pop_all_iret
%endmacro

; pokeq0 dest, value, retaddr
%macro pokeq0 3
memcpy0 (%1), %%value, 8, (%3)
section .data
%%value:
dq (%2)
section .text
%endmacro

; pokeq dest, value
%macro pokeq 2
memcpy (%1), %%value, 8
section .data
%%value:
dq (%2)
section .text
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
section .data
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
cmpw (%1), (%2), (%3), %%next_check, (%5)
%%next_check:
cmpw (%1)+2, (%2)+2, (%3), (%4), (%5)
%endmacro

; cmpq ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpq 5
cmpd (%1)+4, (%2)+4, (%3), %%next_check, (%5)
%%next_check:
cmpd (%1), (%2), (%3), (%4), (%5)
%endmacro

; cmpqbe ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpqbe 5
cmpd (%1), (%2), (%3), %%next_check, (%5)
%%next_check:
cmpd (%1)+4, (%2)+4, (%3), (%4), (%5)
%endmacro

; cmpqi ptr1, imm, is_less, is_equal, is_greater
%macro cmpqi 5
cmpq (%1), %%value, (%3), (%4), (%5)
section .data
%%value:
dq (%2)
section .text
%endmacro

; cmpqibe ptr1, imm, is_less, is_equal, is_greater
%macro cmpqibe 5
cmpqbe (%1), %%value, (%3), (%4), (%5)
section .data
%%value:
dq (%2)
section .text
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
memcpy log_area_cur, %%regs_stash+iret_rdi, 8
%%skip:
%endmacro

; replace_word ptr1, value1, value2
%macro replace_word 3
%%start:
cmpw (%1), %%value1, %%skip, %%change, %%skip
%%change:
memcpy (%1), %%value2, 2
%%skip:
section .data
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
section .data
%%value1:
dw (%2)
%%value2:
dw (%3)
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

; on_rip rip, tgt
%macro on_rip 2
cmpqibe iret_frame, (%1), %%next_check, (%2), %%next_check
%%next_check:
%endmacro

prog_entry:

%include "parasites.inc"

on_rip syscall_before, handle_syscall_before

; generic fallback

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

handle_syscall_before:
decrypt_pointer regs_stash+iret_rax
cmpqibe regs_stash+iret_rax, sysents+48*39, decrypt_end, handle_getppid, decrypt_end

handle_getppid:
pokeq iret_frame, syscall_after
pokeq0 regs_stash+iret_rax, 123456789, doreti_iret
dq pop_all_iret
dq 0x20
dq 2
dq decrypt_end
dq 0

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

; pseudocode:
; comparison_table[a][b] = 8 * (intcmp(a, b) + 1)
section .data.compar
align 65536
comparison_table:
%rep 65536
db ((($-comparison_table)/256 - ($-comparison_table) % 256 + 256) / 256 + (($-comparison_table)/256 - ($-comparison_table) % 256 + 255) / 256) * 8
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
