all: payload.bin

clean:
	rm -f payload.elf payload.bin sender sender.exe

../lib/lib.a:
	cd ../lib; make

payload.elf: ../lib/lib.a main.c
	gcc -g -mcmodel=small -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a main.c download.c ps4-libjbc/*.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	file payload.bin | fgrep -q 'payload.bin: DOS executable (COM)'

sender: sender.c payload.bin
	gcc -D_FILE_OFFSET_BITS=64 sender.c -o sender

sender.exe: sender.c payload.bin
	i686-w64-mingw32-gcc -D_FILE_OFFSET_BITS=64 sender.c -o sender.exe -lws2_32
