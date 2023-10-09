use64

global _start
extern main
extern addr__dynlib_dlsym
extern elf_main
extern _end

section .text.startup ; needed for correct linkage with -O2

_start:
jmp start2
db 'E', 'L', 'F' ; internal magic for the patcher script
dq _sdata-_start
start2:
jmp start3

times 24-($-_start) db 0
dq elf_main-_start
dq 64

times 56-($-_start) db 0
dw 2

times 64-($-_start) db 0

; segment 1 -- rx
dd 1
dd 5
dq 0
dq 0
dq 0
dq _sdata-_start
dq _sdata-_start
dq 0

; segment 2 -- rw
dd 1
dd 6
dq _sdata-_start
dq _sdata-_start
dq _sdata-_start
dq _end-_start
dq _end-_start
dq 0

start3:
mov [rel addr__dynlib_dlsym], rdi
jmp main

section .data
_sdata:
db 1
