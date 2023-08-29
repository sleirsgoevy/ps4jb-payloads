use64

global run_in_kernel
global ret2trace
global kmemcpy
extern copyin
extern copyout
extern kframe
extern uretframe
extern trace_start
extern trace_end
extern trace_prog
extern trace_frame_size

run_in_kernel:
push rax
push rdi
mov rax, rsp
push dword 0x3b
push rax
push dword 0x10202
push dword 0x43
lea rax, [rel .int1_return]
push rax
mov rdi, [rel uretframe]
mov rsi, rsp
mov rdx, 40
call copyin
add rsp, 40
mov rdi, [rsp]
push dword 0
push qword [rdi+56]
mov eax, [rdi+136]
push rax
push dword 0x20
push qword [rdi+128]
mov rdi, [rel kframe]
mov rsi, rsp
mov rdx, 40
call copyin
add rsp, 40
mov rdi, [rsp]
xchg rax, [rdi]
xchg rcx, [rdi+16]
xchg rdx, [rdi+24]
xchg rbx, [rdi+8]
xchg rbp, [rdi+48]
xchg rsi, [rdi+32]
xchg r8, [rdi+64]
xchg r9, [rdi+72]
xchg r10, [rdi+80]
xchg r11, [rdi+88]
xchg r12, [rdi+96]
xchg r13, [rdi+104]
xchg r14, [rdi+112]
xchg r15, [rdi+120]
mov rdi, [rdi+40]
int 9
.int1_return:
xchg rdi, [rsp]
xchg [rdi], rax
xchg [rdi+16], rcx
xchg [rdi+24], rdx
xchg [rdi+8], rbx
xchg [rdi+48], rbp
xchg [rdi+32], rsi
mov rax, [rsp]
mov [rdi+40], rax
xchg [rdi+64], r8
xchg [rdi+72], r9
xchg [rdi+80], r10
xchg [rdi+88], r11
xchg [rdi+96], r12
xchg [rdi+104], r13
xchg [rdi+112], r14
xchg [rdi+120], r15
mov [rsp], rdi
sub rsp, 40
mov rdi, rsp
mov rsi, [rel kframe]
mov rdx, 40
call copyout
mov rdi, [rsp+40]
mov rax, [rsp]
mov [rdi+128], rax
mov rax, [rsp+16]
mov [rdi+136], eax
mov rax, [rsp+24]
mov [rdi+56], rax
add rsp, 56
ret

ret2trace:
push r15
push r14
push r13
push r12
push r11
push r10
push r9
push r8
push rdi
push rsi
push rbp
push dword 0
push rbx
push rdx
push rcx
push rax
sub rsp, 40
mov rdi, rsp
mov rsi, [rel kframe]
mov rdx, 40
call kmemcpy
mov rcx, 168
mov rax, [rel trace_frame_size]
cmp rax, rcx
cmovb rcx, rax
mov rax, [rel trace_end]
sub rax, [rel trace_start]
cmp rax, rcx
cmovb rcx, rax
mov rdi, [rel trace_start]
mov rsi, rsp
rep movsb
mov [rel trace_start], rdi
or byte [rsp+18], 1
cmp qword [rel trace_prog], 0
jz .no_program
mov rdi, rsp
push rbp
call qword [rel trace_prog]
pop rbp
.no_program
mov rdi, [rel kframe]
mov rsi, rsp
mov rdx, 40
call kmemcpy
add rsp, 40
pop rax
pop rcx
pop rdx
pop rbx
pop rbp
pop rbp
pop rsi
pop rdi
pop r8
pop r9
pop r10
pop r11
pop r12
pop r13
pop r14
pop r15
int 9

kmemcpy:
mov rcx, rdx
mov rax, rbp
int 179
mov rbp, rax
ret
