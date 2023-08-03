all: payload.bin prosper0gdb.o

clean:
	rm -f payload.elf payload.bin r0run.o prosper0gdb.o

../lib/lib.a:
	cd ../lib; make

r0run.o: r0run.asm
	yasm -f elf64 r0run.asm

prosper0gdb.o: r0gdb.c r0run.o
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -r -ffunction-sections -fdata-sections r0gdb.c r0run.o -o prosper0gdb.o -fPIE -ffreestanding

payload.elf: ../lib/lib.a main.c prosper0gdb.o dbg.c 
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a main.c prosper0gdb.o dbg.c -o payload.elf -fPIE -ffreestanding -Wl,-no-pie

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	file payload.bin | fgrep -q 'payload.bin: DOS executable (COM)'
