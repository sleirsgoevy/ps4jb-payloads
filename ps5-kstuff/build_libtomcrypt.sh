cd libtomcrypt
for i in clean -j$(nproc); do make CC='gcc -nostdlib -nostdinc -isystem /proc/'$$'/cwd/../../freebsd-headers -O3 -march=x86-64-v3 -g -ffreestanding -mgeneral-regs-only -ffunction-sections -fdata-sections -fPIE -fPIC -fvisibility=hidden -include /proc/'$$'/cwd/../overrides.h' $i; done
