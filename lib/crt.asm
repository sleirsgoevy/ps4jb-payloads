use64

global _start
global rfork
extern main
extern addr__dynlib_dlsym
extern rfork_thread

section .text.startup ; needed for correct linkage with -O2

_start:
jmp start2
db 'P', 'L', 'D'
dq _sdata-_start
start2:
mov [rel addr__dynlib_dlsym], rdi
jmp main

section .data
_sdata:
db 1

section .text.rfork

rfork:
push rbp
push rbx
push r12
push r13
push r14
push r15
push rax
mov rsi, rsp
lea rdx, [rel .child_thunk]
mov rcx, rsp
call rfork_thread
.exit:
pop r15
pop r15
pop r14
pop r13
pop r12
pop rbx
pop rbp
ret
.child_thunk:
mov rsp, rdi
xor eax, eax
jmp .exit
