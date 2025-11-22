use64

%macro spam 0
mov eax, 0xc1010100
%%loop:
test dword [eax+12], 0x800
jnz %%loop
mov dword [eax+4], '!'
db 0xeb, 0xfe
%endmacro

section .header
global _start
global reset_vector
extern hijack_cpus
extern boot_cpu_init
extern persist_start
extern pml4
extern apic_base
extern firmware_wakeup_table
extern ref_tsc
extern ref_seconds

%macro smp_barrier 1
lock inc dword [rel counter]
%%wait:
cmp dword [rel counter], (%1)
jb %%wait
%endmacro

_start:
mov r12, qword persist_start - _start ; target where to copy
mov r13, qword 0 ; size of the copy
mov r14, qword 0 ; zero page
mov r15, qword 0 ; entrypoint
mov rax, qword 0 ; tsc at reference time
mov rcx, qword 0 ; secods since epoch at reference time

; save the reference time. we use it to provide a fake RTC to Linux
mov [rel ref_tsc], rax
mov [rel ref_seconds], rcx

; however we came here, we need to signal EOI to the local APIC
mov ecx, 0x1b
rdmsr
and eax, -4096
shl rdx, 32
lea rdi, [rax+rdx]
mov dword [rdi+0xb0], 0

; the core may've been booted in ps4 mode. let's switch to ps5 mode
mov eax, 5
vmmcall

; the first cpu gets here from strlen_trap. other cpus are brought here by hijack_cpus
lock inc dword [rel counter]
cmp dword [rel counter], 1
jnz .not_first_cpu

; bring up other cpus
lea rsp, [rel stack_end]
call hijack_cpus

.not_first_cpu:
; do not start copying until all other cores have left the *BSD
smp_barrier 32

; at this point, all 16 cpus have entered the trampoline
mov eax, 11
cpuid ; edx = our own apic id
test edx, edx
jnz .skip_copy ; only the boot cpu does the copy

mov rdi, r12
lea rsi, [rel _start]
mov rcx, r13
rep movsb
mov dword [r12+(counter)-_start], 48

.skip_copy:
smp_barrier 48
lea rax, [r12+(.post_reloc)-_start]
jmp rax

.post_reloc:
smp_barrier 64

; set up a sane gdt for ourselves
lea rax, [rel gdt]
mov [rel gdtr+2], rax
lgdt [rel gdtr]

; set cs. edx still contains the apic id
lea rax, [2*rdx]
lea rcx, [rel stack]
lea rsp, [rcx+8*rax]
lea rax, [rel .ret]
push dword 16
push rax
retf
.ret:
xor eax, eax
mov ds, ax
mov es, ax
mov ss, ax
mov fs, ax
mov gs, ax

; before calling c, make sure every thread exited the stack
smp_barrier 80

; edx still contains the apic id
test edx, edx
jnz .skip_init

lea rsp, [rel stack_end]
mov rdi, r14
call boot_cpu_init
xor edx, edx

.skip_init:
smp_barrier 96

; boot cpu now proceeds to boot linux. other cpus enter the "firmware wakeup" spinloop
lea rax, [rel spinloop]
test edx, edx
jne .skip_barrier
smp_barrier 112
mov rax, r15
.skip_barrier:

imul edx, edx, 40
lea rcx, [rel stack]
lea rsp, [rcx+rdx]
mov [rsp], rax
mov eax, 16
mov [rsp+8], rax
mov eax, 2
mov [rsp+16], rax
xor eax, eax
mov [rsp+24], rax
mov eax, 24
mov [rsp+32], rax

mov ds, ax
mov es, ax
mov ss, ax
mov fs, ax
mov gs, ax

lea rax, [rel pml4]
mov cr3, rax

mov rsi, r14
xor eax, eax
xor ecx, ecx
xor edx, edx
xor ebx, ebx
xor ebp, ebp
xor edi, edi
xor r8d, r8d
xor r9d, r9d
xor r10d, r10d
xor r11d, r11d
xor r12d, r12d
xor r13d, r13d
xor r14d, r14d
xor r15d, r15d
iretq

counter:
dd 0

section .persist
gdtr:
dw 31
dq 0

gdt:
dq 0
dq 0
db 0xff, 0xff, 0, 0, 0, 0x9a, 0xaf, 0
db 0xff, 0xff, 0, 0, 0, 0x92, 0xcf, 0

spinloop:
; do not boot linux until all other cores get here
lock inc dword [rel counter]

reset_vector:
mov eax, 11
cpuid ; edx = apic id
shl rdx, 32
or rdx, 1

.spinloop:
cmp qword [rel firmware_wakeup_table], rdx
jne .spinloop

mov rdi, [rel firmware_wakeup_table+8]
mov byte [rel firmware_wakeup_table], 0

; reacknowledge the APIC here one last time
mov ecx, 0x1b
rdmsr
and eax, -4096
shl rdx, 32
mov dword [rax+rdx+0xb0], 0

xor eax, eax
xor ecx, ecx
xor edx, edx
jmp rdi

section .bss
align 4096
stack:
times 4096 db 0
stack_end:
