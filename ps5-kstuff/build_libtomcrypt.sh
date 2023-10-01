cd libtomcrypt
for i in clean -j$(nproc); do make CC='gcc -nostdlib -nostdinc -isystem /proc/'$$'/cwd/../../freebsd-headers -isystem /nix/store/b7hvml0m3qmqraz1022fwvyyg6fc1vdy-gcc-12.2.0/lib/gcc/x86_64-unknown-linux-gnu/12.2.0/include -O0 -g -ffreestanding -mgeneral-regs-only -ffunction-sections -fdata-sections -fPIE -fPIC -fvisibility=hidden -include /proc/'$$'/cwd/../overrides.h' $i; done
