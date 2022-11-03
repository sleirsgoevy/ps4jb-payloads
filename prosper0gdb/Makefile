all: payload.bin

clean:
	rm -f payload.elf payload.bin r0run.o

../lib/lib.a:
	cd ../lib; make

r0run.o: r0run.asm
	yasm -f elf64 r0run.asm

payload.elf: ../lib/lib.a main.c r0gdb.c dbg.c r0run.o
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a main.c r0gdb.c r0run.o dbg.c -o payload.elf -fPIE -ffreestanding

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	file payload.bin | fgrep -q 'payload.bin: DOS executable (COM)'
