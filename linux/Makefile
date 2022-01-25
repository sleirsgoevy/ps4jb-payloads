all: payload.bin payload-3gb.bin payload-702.bin payload-702-3gb.bin payload-755.bin payload-755-3gb.bin payload-900.bin payload-900-3gb.bin

clean:
	rm -f payload.elf payload.bin payload-702.elf payload-702.bin payload-755.elf payload-755.bin payload-900.elf payload-900.bin payload-3gb.elf payload-3gb.bin payload-702-3gb.elf payload-702-3gb.bin payload-755-3gb.elf payload-755-3gb.bin payload-900-3gb.elf payload-900-3gb.bin

../lib/lib.a:
	cd ../lib; make

payload.elf: ../lib/lib.a main.c ps4-kexec-672/kexec.bin
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a -D__6_72__ main.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding

payload-702.elf: ../lib/lib.a main.c ps4-kexec-702/kexec.bin
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a -D__7_02__ main.c -Wl,-gc-sections -o payload-702.elf -fPIE -ffreestanding

payload-755.elf: ../lib/lib.a main.c ps4-kexec-755/kexec.bin
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a -D__7_55__ main.c -Wl,-gc-sections -o payload-755.elf -fPIE -ffreestanding

payload-900.elf: ../lib/lib.a main.c ps4-kexec-900/kexec.bin
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a -D__9_00__ main.c -Wl,-gc-sections -o payload-900.elf -fPIE -ffreestanding

payload-3gb.elf: ../lib/lib.a main.c ps4-kexec-672/kexec.bin
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a -D__6_72__ -DVRAM_GB_DEFAULT=3 main.c -Wl,-gc-sections -o payload-3gb.elf -fPIE -ffreestanding

payload-702-3gb.elf: ../lib/lib.a main.c ps4-kexec-702/kexec.bin
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a -D__7_02__ -DVRAM_GB_DEFAULT=3 main.c -Wl,-gc-sections -o payload-702-3gb.elf -fPIE -ffreestanding

payload-755-3gb.elf: ../lib/lib.a main.c ps4-kexec-755/kexec.bin
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a -D__7_55__ -DVRAM_GB_DEFAULT=3 main.c -Wl,-gc-sections -o payload-755-3gb.elf -fPIE -ffreestanding

payload-900-3gb.elf: ../lib/lib.a main.c ps4-kexec-900/kexec.bin
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib.a -D__9_00__ -DVRAM_GB_DEFAULT=3 main.c -Wl,-gc-sections -o payload-900-3gb.elf -fPIE -ffreestanding

%.bin: %.elf
	objcopy $< --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary $@
	file $@ | fgrep -q '$@: DOS executable (COM)'

ps4-kexec-%/kexec.bin:
	cd ps4-kexec-$*; make
