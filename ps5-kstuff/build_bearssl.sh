cd BearSSL
for i in clean "lib -j$(nproc)"; do make CC='gcc -nostdlib -nostdinc -isystem /proc/'$$'/cwd/../../freebsd-headers -O0 -g -ffreestanding -mgeneral-regs-only -ffunction-sections -fdata-sections -fvisibility=hidden -include /proc/'$$'/cwd/../overrides.h' $i; done
