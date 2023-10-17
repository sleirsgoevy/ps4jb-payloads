all: payload.bin

clean:
	rm -f payload.elf payload.bin

../lib/lib-elf.a:
	cd ../lib; make

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; make

payload.elf: ../lib/lib-elf.a ../prosper0gdb/prosper0gdb.o main.c ../prosper0gdb/dbg.c
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf.a ../prosper0gdb/prosper0gdb.o $(EXTRA_CFLAGS) main.c ../prosper0gdb/dbg.c -o payload.elf -fPIE -ffreestanding -Wl,-zcommon-page-size=16384 -Wl,-no-pie -Wl,-zmax-page-size=16384

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	python3 ../lib/frankenelf.py payload.bin
