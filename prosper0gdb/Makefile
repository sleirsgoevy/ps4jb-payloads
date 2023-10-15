all: payload.bin prosper0gdb.o

clean:
	rm -f payload.elf payload.bin r0run.o prosper0gdb.o

../lib/lib-elf.a:
	cd ../lib; make

r0run.o: r0run.asm
	yasm -f elf64 -g dwarf2 r0run.asm -o r0run.o

prosper0gdb.o: r0gdb.c r0run.o offsets.c offsets.h offset_list.txt
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -r -Wl,--unique='*' -ffunction-sections -fdata-sections $(EXTRA_CFLAGS) r0gdb.c r0run.o offsets.c -o prosper0gdb.o -fPIE -ffreestanding

payload.elf: ../lib/lib-elf.a main.c prosper0gdb.o dbg.c 
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf.a $(EXTRA_CFLAGS) main.c prosper0gdb.o dbg.c -o payload.elf -fPIE -ffreestanding -Wl,-no-pie -Wl,-zmax-page-size=16384 -Wl,-zcommon-page-size=16384

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	python3 ../lib/frankenelf.py payload.bin
