use64

global trampoline
global trampoline_end
global memcpy
global memset

trampoline:
incbin "trampoline/payload.bin"
trampoline_end:

memcpy:
mov rax, rdi
mov rcx, rdx
rep movsb
ret

memset:
mov rax, rsi
mov rsi, rdi
mov rcx, rdx
rep stosb
mov rax, rsi
ret
