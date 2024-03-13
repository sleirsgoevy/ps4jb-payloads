use64

global r0hook_start
global r0hook_int1
global r0hook_int3
global r0hook_int13
global r0hook_real_int1
global r0hook_real_int3
global r0hook_real_int13
global r0hook_mailbox
global r0hook_end

;; TODO: be more efficient than a busy loop

section .text

r0hook_start:

r0hook_int13:
test byte [rsp+8], 3
jnz r0hook_go_real13
push dword 13
jmp r0hook_entry

r0hook_int1:
test byte [rsp+8], 3
jnz r0hook_go_real1
push dword 1
jmp r0hook_entry

r0hook_int3:
test byte [rsp+8], 3
jnz r0hook_go_real3
push dword 3
; fallthrough

r0hook_entry:
; move to the caller's stack and enable interrupts
cld
sub rsp, 48
push rdi
push rsi
push rcx
lea rdi, [rsp+24]
lea rsi, [rsp+72]
mov ecx, 6
rep movsq
mov rdi, [rsp+56]
sub rdi, 48
lea rsi, [rsp+24]
mov ecx, 6
rep movsq
pop rcx
pop rsi
pop rdi
mov rsp, [rsp+32]
sub rsp, 48

r0hook_main:
xchg rax, [rsp]
push rcx
push rdx
push rbx
push rax ; interrupt no
push rbp
push rsi
push rdi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
mov rax, qword [gs:0]
push rax ; curthread

cmpxchg_loop:
cli
mov rax, cr0
btc rax, 16
mov cr0, rax
xor eax, eax
lock cmpxchg [rel r0hook_mailbox], rsp
sete cl
mov rax, cr0
bts rax, 16
mov cr0, rax
sti
test cl, cl
jz cmpxchg_loop

r0hook_loop:
cmp qword [rel r0hook_mailbox], 1
jnz r0hook_loop

cli
mov rax, cr0
btc rax, 16
mov cr0, rax
mov qword [rel r0hook_mailbox], 0
mov rax, cr0
bts rax, 16
mov cr0, rax
sti

pop rax
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rbp
pop rax
pop rbx
pop rdx
pop rcx
pop rax
iretq

r0hook_go_real1:
jmp [rel r0hook_real_int1]

r0hook_go_real3:
jmp [rel r0hook_real_int3]

r0hook_go_real13:
jmp [rel r0hook_real_int13]

r0hook_real_int1:
dq 0

r0hook_real_int3:
dq 0

r0hook_real_int13:
dq 0

r0hook_mailbox:
dq 0

r0hook_end:
