all: payload.bin

clean:
	rm -f payload.elf payload.bin freebsd-loader kelf kelf.o structs.h structs.inc uelf/uelf uelf/crt.o

../lib/lib.a:
	cd ../lib; make

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; make

structs.inc: structs-ps5.inc
	cp structs-ps5.inc structs.inc

payload.elf: ../lib/lib.a ../prosper0gdb/prosper0gdb.o main.c kelf uelf/uelf
	#gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a ../prosper0gdb/prosper0gdb.o -DDEBUG main.c ../prosper0gdb/dbg.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a ../prosper0gdb/prosper0gdb.o -DDEBUG main.c ../prosper0gdb/dbg.c -o payload.elf -fPIE -ffreestanding

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	file payload.bin | fgrep -q 'payload.bin: DOS executable (COM)'

kelf.o: kelf.asm structs.inc
	yasm -f elf64 -g dwarf2 kelf.asm -o kelf.o

kelf: kelf.o
	gcc -nostdlib -shared kelf.o -o kelf

structs.h: structs.inc
	sed 's/^%/#/' structs.inc > structs.h

uelf/crt.o: uelf/crt.asm
	yasm uelf/crt.asm -f elf64 -o uelf/crt.o

uelf/uelf: uelf/*.c uelf/*.h structs.h uelf/crt.o
	gcc -Wl,-Bsymbolic -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -mgeneral-regs-only -fno-stack-protector -fPIE -fPIC -shared -ffreestanding -fno-builtin uelf/crt.o uelf/*.c -o uelf/uelf
