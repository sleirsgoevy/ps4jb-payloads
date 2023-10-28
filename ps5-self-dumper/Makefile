all: payload.bin payload-gdb.bin

clean:
	rm -f payload.elf payload.bin payload-gdb.elf payload-gdb.bin

../lib/lib.a:
	cd ../lib; make

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; make

payload.elf: ../lib/lib-elf.a ../prosper0gdb/prosper0gdb.o main.c
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static $(EXTRA_CFLAGS) ../lib/lib-elf.a ../prosper0gdb/prosper0gdb.o main.c -ffunction-sections -fdata-sections -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -Wl,-no-pie -Wl,-zmax-page-size=16384 -Wl,-zcommon-page-size=16384

payload-gdb.elf: ../lib/lib-elf.a ../prosper0gdb/prosper0gdb.o main.c
	gcc -O0 -g -DDEBUG -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static $(EXTRA_CFLAGS) ../lib/lib-elf.a ../prosper0gdb/prosper0gdb.o main.c ../prosper0gdb/dbg.c -o payload-gdb.elf -fPIE -ffreestanding -Wl,-no-pie -Wl,-zmax-page-size=16384 -Wl,-zcommon-page-size=16384

payloa%.bin: payloa%.elf
	objcopy $< --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary $@
	python3 ../lib/frankenelf.py $@
