use64

global _start
extern main
extern addr__dynlib_dlsym

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
