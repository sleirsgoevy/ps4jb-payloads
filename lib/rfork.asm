section .text.rfork

extern rfork_thread

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
