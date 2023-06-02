all: payload.bin

clean:
	rm -f payload.elf payload.bin kek kek.o

../lib/lib.a:
	cd ../lib; make

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; make

payload.elf: ../lib/lib.a ../prosper0gdb/prosper0gdb.o main.c kek
	#gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a ../prosper0gdb/prosper0gdb.o -DDEBUG main.c ../prosper0gdb/dbg.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a ../prosper0gdb/prosper0gdb.o -DDEBUG main.c ../prosper0gdb/dbg.c -o payload.elf -fPIE -ffreestanding

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	file payload.bin | fgrep -q 'payload.bin: DOS executable (COM)'

kek.o: kek.asm structs.inc parasites.inc fself.inc fself_hooks.inc fself_syscalls.inc
	yasm -f elf64 -g dwarf2 kek.asm -o kek.o

kek: kek.o
	gcc -nostdlib -shared kek.o -o kek
