all: payload.bin

clean:
	rm -f entry.o payload.elf payload.bin

entry.o: entry.asm
	yasm -f elf64 entry.asm -o entry.o

payload.elf: link.x entry.o *.c
	gcc -O3 -isystem ../../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static -fPIE -ffreestanding -no-pie -mgeneral-regs-only -mno-red-zone -Wl,-T,link.x entry.o *.c -o payload.elf

payload.bin: payload.elf
	objcopy --dump-section .text=payload.bin payload.elf /dev/null
