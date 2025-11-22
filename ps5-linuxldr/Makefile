all: payload.bin payload-gdb.bin

clean:
	rm -f payload.elf payload.bin trampoline.o
	cd trampoline; make clean

../lib/lib-elf-ps5.a:
	cd ../lib; make

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; make

trampoline.o: trampoline.asm trampoline/payload.bin
	yasm -f elf64 $< -o $@

trampoline/payload.bin: trampoline/Makefile trampoline/link.x trampoline/entry.asm trampoline/*.c
	cd trampoline; make

payload.elf: ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o main.c memmap.c trampoline.o
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o $(EXTRA_CFLAGS) -DNDEBUG main.c memmap.c trampoline.o -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -no-pie -Wl,-z,max-page-size=16384 -Wl,-zcommon-page-size=16384

payload-gdb.elf: ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o main.c memmap.c trampoline.o
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o $(EXTRA_CFLAGS) main.c memmap.c trampoline.o -DPS5KEK ../prosper0gdb/dbg.c -o payload-gdb.elf -fPIE -ffreestanding -no-pie -Wl,-z,max-page-size=16384 -Wl,-zcommon-page-size=16384

payloa%.bin: payloa%.elf
	objcopy $< --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary $@
	python3 ../lib/frankenelf.py $@
