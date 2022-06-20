use64

extern log_syscall_args
extern log_syscall_ans
global strace_log_start
global strace_log_end

;; hook format:
; call strace_log_start ; 6 bytes
; syscall ; 2 bytes
; call strace_log_end ; 6 bytes
; dq strace_log_start ; 8 bytes
; dq strace_log_end ; 8 bytes
; dq jump_next ; 8 bytes
; dd sysc ; 4 bytes

strace_log_start:
mov rax, [rsp]
mov eax, [rax+32]
push r9
push r8
push rcx
push rdx
push rsi
push rdi
push rax
mov rdi, rsp
push rbp
mov rbp, rsp
and rsp, -16
call log_syscall_args
leave
pop rax
pop rdi
pop rsi
pop rdx
pop r10
pop r8
pop r9
ret

strace_log_end:
push rax
push rdx
push rsi
push rdi
pushfq
mov rcx, rax
mov r8, [rsp]
mov r9, [rsp+40]
mov r9d, [r9+24]
push rbp
mov rbp, rsp
and rsp, -16
call log_syscall_ans
leave
popfq
pop rdi
pop rsi
pop rdx
pop rax
pop r11
jmp [r11+16]
