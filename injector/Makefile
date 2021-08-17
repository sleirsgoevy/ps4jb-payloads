all: payload.bin payload-702.bin payload-755.bin

clean:
	rm -f payload.elf payload.bin payload-702.elf payload-702.bin payload-755.elf payload-755.bin

../lib/lib.a:
	cd ../lib; make

payload.elf: ../lib/lib.a main.c
	gcc -mno-red-zone -g -isystem ../freebsd-headers -nostdinc -nostdlib -static ../lib/lib.a main.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	file payload.bin | fgrep -q 'payload.bin: DOS executable (COM)'

payload-702.elf: ../lib/lib.a main.c
	gcc -mno-red-zone -g -isystem ../freebsd-headers -nostdinc -nostdlib -static ../lib/lib.a -D__7_02__ main.c -Wl,-gc-sections -o payload-702.elf -fPIE -ffreestanding

payload-702.bin: payload-702.elf
	objcopy payload-702.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload-702.bin
	file payload-702.bin | fgrep -q 'payload-702.bin: DOS executable (COM)'

payload-755.elf: ../lib/lib.a main.c
	gcc -mno-red-zone -g -isystem ../freebsd-headers -nostdinc -nostdlib -static ../lib/lib.a -D__7_55__ main.c -Wl,-gc-sections -o payload-755.elf -fPIE -ffreestanding

payload-755.bin: payload-755.elf
	objcopy payload-755.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload-755.bin
	file payload-755.bin | fgrep -q 'payload-755.bin: DOS executable (COM)'
