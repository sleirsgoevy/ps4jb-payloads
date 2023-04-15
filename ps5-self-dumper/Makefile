all: payload.bin

clean:
	rm -f payload.elf payload.bin

../lib/lib.a:
	cd ../lib; make

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; make

payload.elf: ../lib/lib.a ../prosper0gdb/prosper0gdb.o main.c
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a ../prosper0gdb/prosper0gdb.o main.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -Wl,-no-pie

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	file payload.bin | fgrep -q 'payload.bin: DOS executable (COM)'
