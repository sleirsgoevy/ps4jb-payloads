section .text
use64

global yield
global memcpy
global cr3_phys
global trap_frame
global _start
extern main

yield:
push rbp
push rbx
push r12
push r13
push r14
push r15
mov [rel saved_rsp], rsp
hlt

memcpy:
mov rax, rdi
mov rcx, rdx
rep movsb
ret

; rdi = trap_frame
; rsi = cr3 of caller
; rdx = our cr3 (currently unused)
; rcx = justreturn frame (has saved rax/rcx/rdx)
_start:
mov [rel trap_frame], rdi
mov [rel cr3_phys], rsi
xor rsp, rsp
xchg rsp, [rel saved_rsp]
test rsp, rsp
jnz .unyield
lea rsp, [rel stack+16384]
mov rdi, rcx
call main
hlt
.unyield:
mov rax, rcx
pop r15
pop r14
pop r13
pop r12
pop rbx
pop rbp
ret

section .bss
align 16
trap_frame:
resq 1
cr3_phys:
resq 1
stack:
resb 16384
saved_rsp:
dq 0
