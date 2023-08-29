all: lib.a lib-ps5.a

clean:
	rm -f lib.a lib-ps5.a *.o syscalls.asm syscalls-ps5.asm

dl.o: dl.c
	gcc -c -isystem ../freebsd-headers -nostdinc -fno-stack-protector dl.c -o dl.o -fPIE -ffreestanding

crt.o: crt.asm
	yasm -f elf64 crt.asm

rfork.o: rfork.asm
	yasm -f elf64 rfork.asm

syscalls.o: syscalls.asm
	yasm -f elf64 syscalls.asm

syscalls.asm: syscalls.py syscalls.txt
	python3 syscalls.py > syscalls.asm

syscalls-ps5.o: syscalls-ps5.asm
	yasm -f elf64 syscalls-ps5.asm

syscalls-ps5.asm: syscalls-ps5.py
	python3 syscalls-ps5.py > syscalls-ps5.asm

lib.a: crt.o rfork.o dl.o syscalls.o
	ld -r crt.o rfork.o dl.o syscalls.o -o lib.a

lib-ps5.a: crt.o dl.o syscalls-ps5.o
	ld -r crt.o dl.o syscalls-ps5.o -o lib-ps5.a
