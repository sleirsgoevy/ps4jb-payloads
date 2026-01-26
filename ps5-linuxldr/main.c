#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <kenv.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#define sysctl __sysctl
#include <sys/sysctl.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"
#include "../gdb_stub/dbg.h"
#include "memmap.h"

uint64_t virt2phys(uintptr_t addr)
{
    uint64_t dmap = r0gdb_get_dmap_base();
    uint64_t pml = r0gdb_read_cr3();
    for(int i = 39; i >= 12; i -= 9)
    {
        uint64_t inner_pml;
        copyout(&inner_pml, dmap+pml+((addr & (0x1ffull << i)) >> (i - 3)), 8);
        if(!(inner_pml & 1)) //not present
            return -1;
        if((inner_pml & 128) || i == 12) //hugepage
        {
            inner_pml &= (1ull << 52) - (1ull << i);
            inner_pml |= addr & ((1ull << i) - 1);
            return inner_pml;
        }
        inner_pml &= (1ull << 52) - (1ull << 12);
        pml = inner_pml;
    }
    //unreachable
}

void* dlsym(void*, const char*);

static uint64_t alloc_page(void)
{
    //looks like in-kernel malloc is the only way to reliably allocate memory that won't be freed/paged out on reboot
    static uint64_t kva_start, kva_end;
    if(kva_start == kva_end)
    {
        enum { SIZE = 1 << 24 };
        kva_start = r0gdb_kmalloc(SIZE);
        kva_end = kva_start + SIZE;
    }
    uint64_t ans = kva_start;
    kva_start += 4096;
    return virt2phys(ans);
}

static void map_page(uint64_t cr3, uint64_t virt)
{
    uint64_t dmap = r0gdb_get_dmap_base();
    static char empty_page[4096];
    uint64_t pml = cr3;
    for(size_t i = 39; i >= 12; i -= 9)
    {
        size_t id = (virt >> i) & 511;
        uint64_t slot;
        copyout(&slot, dmap+pml+8*id, 8);
        if(!(slot & 1))
        {
            slot = alloc_page();
            copyin(dmap+slot, empty_page, 4096);
            slot |= 7;
            copyin(dmap+pml+8*id, &slot, 8);
        }
        pml = slot & ((1ull << 52) - (1ull << 12));
    }
}

static int blacklist_page(struct memmap* mm, uint64_t cr3, uint64_t virt)
{
    uint64_t pml = cr3;
    uint64_t dmap = r0gdb_get_dmap_base();
    for(size_t i = 39; i >= 12; i -= 9)
    {
        memmap_add_bad_region(mm, pml, pml+4096);
        uint64_t entry;
        copyout(&entry, dmap + pml + 8 * ((virt >> i) & 511), 8);
        if(!(entry & 1))
            return -1;
        if((entry & 0x80))
        {
            pml = (entry & ((1ull << 52) - (1ull << i))) | (virt & ((1ull << i) - (1ull << 12)));
            break;
        }
        pml = entry & ((1ull << 52) - (1ull << 12));
    }
    memmap_add_bad_region(mm, pml, pml+4096);
    return 0;
}

static void receive_linux(char** p_p, size_t* p_sz, const char* backup_file)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, 4);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = __builtin_bswap16(9999),
    };
    bind(sock, (void*)&sin, sizeof(sin));
    listen(sock, 1);
    int sock2 = accept(sock, 0, 0);
    close(sock);
    char* addr = mmap(0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    uint64_t size = 0;
    uint64_t cap = 16384;
    for(;;)
    {
        if(size == cap)
        {
            uint64_t cap2 = cap * 2;
            char* addr2 = mmap(0, cap2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
            for(size_t i = 0; i < size; i++)
                addr2[i] = addr[i];
            munmap(addr, cap);
            addr = addr2;
            cap = cap2;
        }
        ssize_t chk = read(sock2, addr+size, cap-size);
        if(chk < 0)
            asm volatile("ud2");
        if(chk == 0)
            break;
        size += chk;
    }
    close(sock2);
    if(size == 0)
    {
        int fd = open(backup_file, O_RDONLY);
        if(fd >= 0)
        {
            size = lseek(fd, 0, SEEK_END);
            addr = mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
            lseek(fd, 0, SEEK_SET);
            read(fd, addr, size);
            close(fd);
        }
    }
    else
    {
        int fd = open(backup_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(fd >= 0)
        {
            write(fd, addr, size);
            close(fd);
        }
    }
    *p_p = addr;
    *p_sz = size;
}

extern char trampoline[];
extern char trampoline_end[];

void* memcpy(void* dst, const void* src, size_t sz);
void* memset(void* dst, int byte, size_t sz);

static uint64_t get_acpi_rsdp(void)
{
    char buf[19];
    if(kenv(KENV_GET, "acpi.rsdp", buf, sizeof(buf)) != sizeof(buf))
        asm volatile("ud2");
    uint64_t ans = 0;
    for(size_t i = 2; i < 18; i++)
    {
        ans *= 16;
        char c = buf[i];
        if(c >= 'a' && c <= 'z')
            ans += c - 'a' + 10;
        else if(c >= 'A' && c <= 'Z')
            ans += c - 'A' + 10;
        else if(c >= '0' && c <= '9')
            ans += c - '0';
        else
            asm volatile("ud2");
    }
    return ans;
}

#ifdef linux
#undef linux
#endif

struct e820_map_entry e820_map[] = {
    {0x0, 0x1000, 2},
    {0x1000, 0x6f000, 1},
    {0x70000, 0x30000, 2},
    {0xa0000, 0x20000, 2},
    {0xc0000, 0x40000, 2},
    {0x100000, 0x3fefc000, 1},
    {0x3fffc000, 0x4000, 1},
    {0x40000000, 0x20000000, 1},
    {0x60000000, 0xc00000, 2},
    {0x60c00000, 0x1c00000, 1},
    {0x62800000, 0x2029000, 2},
    {0x64829000, 0x1b1a7000, 1},
    {0x7f9d0000, 0x38f000, 2},
    {0x7fd5f000, 0x4000, 2},
    {0x7fd63000, 0x4000, 2},
    {0x7fd67000, 0x8000, 4},
    {0x7fd6f000, 0x20000, 3},
    {0x7fd8f000, 0x1000, 2},
    {0x7fd90000, 0x270000, 2},
    {0x80000000, 0x44210000, 2},
    {0xd0000000, 0x10700000, 2},
    {0xf0000000, 0x8000000, 2},
    {0x100000000, 0x37f300000, 1},
    {0x47f300000, 0xd00000, 2},
};

extern uint64_t kdata_base;

#ifdef NDEBUG
#define dbg_enter()
#define DBG(x)
#else
#define DBG(x) gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)x, (uintptr_t)(sizeof(x)-1))
#endif

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    if(r0gdb_init(ds, a, b, c, d))
        return 1;
    char* linux;
    size_t linux_size;
    receive_linux(&linux, &linux_size, "/user/bzImage");
    char* initrd;
    size_t initrd_size;
    receive_linux(&initrd, &initrd_size, "/user/initramfs.cpio.gz");
    dbg_enter();
    //this allocation seems to somewhat help with annoying boot-time memory corruptions
    //no idea why, maybe this is just a placebo, but it doesn't hurt given how much memory the ps5 has
    r0gdb_kmalloc(1 << 28);
    if(linux_size < 0x1f2)
        asm volatile("ud2");
    int sects = (uint8_t)linux[0x1f1];
    if(!sects)
        sects = 4;
    sects++;
    size_t zero_page_size = (size_t)sects * 512;
    if(sects < 9 || linux_size < zero_page_size)
        asm volatile("ud2");
    size_t kernel_misalignment = (-zero_page_size) & 4095;
    uint64_t addr = 1ull << 39;
    uint64_t base = addr;
    DBG("Mapping trampoline and temporary pagetables... ");
    uint64_t cr3 = r0gdb_read_cr3();
    for(uint64_t i = addr; i < addr + (uintptr_t)trampoline_end - (uintptr_t)trampoline; i += 4096)
        map_page(cr3, i);
    memcpy((void*)addr, trampoline, (uintptr_t)trampoline_end - (uintptr_t)trampoline);
    addr += ((uintptr_t)trampoline_end - (uintptr_t)trampoline + 4095) & -4096;
    uint64_t pml4_for_linux = addr;
    map_page(cr3, addr);
    addr += 4096;
    uint64_t pml3_for_linux = addr;
    map_page(cr3, addr);
    addr += 4096;
    memset((void*)pml4_for_linux, 0, 8192);
    uint64_t initrd_addr = addr;
    for(uint64_t i = addr; i < addr + initrd_size; i += 4096)
        map_page(cr3, i);
    memcpy((void*)initrd_addr, initrd, initrd_size);
    addr = (initrd_addr + initrd_size + 4095) & -4096;
    addr += kernel_misalignment;
    *(uint64_t*)pml4_for_linux = virt2phys(pml3_for_linux) | 3;
    copyout((uint64_t*)(pml4_for_linux+8), r0gdb_get_dmap_base()+cr3+8, 4088);
    uint64_t* pml3t = (uint64_t*)pml3_for_linux;
    for(size_t i = 0; i < 512; i++)
        pml3t[i] = (i << 30) | 131;
    DBG("done\nCopying Linux into virtual memory... ");
    for(uint64_t i = addr; i < addr + linux_size; i = (i + 4096) & -4096)
        map_page(cr3, i);
    memcpy((void*)addr, linux, linux_size);
    memset((void*)addr, 0, 0x1f1);
    size_t zero_page_end = 0x202 + *(uint8_t*)(addr+0x201);
    memset((void*)(addr+zero_page_end), 0, zero_page_size-zero_page_end);
    DBG("done\nPreparing arguments... ");
    if(*(uint16_t*)(addr+0x1fe) != 0xaa55 || *(uint32_t*)(addr+0x202) != *(uint32_t*)"HdrS")
        asm volatile("ud2");
    uint16_t version = (uint8_t)linux[0x207] << 8 | (uint8_t)linux[0x206];
    if(version < 0x200 + 13)
        asm volatile("ud2");
    *(uint8_t*)(addr + 0x210) = 0xd0;
    *(uint8_t*)(addr + 0x211) = ((uint8_t)linux[0x211] | 0xa1) ^ 0x80;
    *(uint16_t*)(addr + 0x226) = 0;
    *(uint32_t*)(addr + 0x23c) = 6; //X86_SUBARCH_PS5
    *(uint64_t*)(addr + 0x70) = get_acpi_rsdp();
#define CMDLINE "nokaslr dis_ucode_ldr console=ttyTitania0 earlycon=titania tsc_early_khz=1596300 disable_mtrr_trim pci=nocrs idle=halt" //amdgpu.discovery=2 amdgpu.ip_block_mask=0xc7"
    memcpy((void*)addr+4096, CMDLINE, sizeof(CMDLINE));
#undef CMDLINE
    DBG("done\nPreparing memory map... ");
    struct memmap mm = {};
    for(size_t i = 0; i < sizeof(e820_map) / sizeof(*e820_map); i++)
        if(e820_map[i].type == 1)
            memmap_add_good_region(&mm, e820_map[i].start, e820_map[i].start + e820_map[i].size);
        else
            memmap_add_bad_region(&mm, e820_map[i].start, e820_map[i].start + e820_map[i].size);
    DBG("blacklisting BSD kernel... ");
    for(uint64_t ptr = kdata_base; !blacklist_page(&mm, cr3, ptr -= 4096););
    for(uint64_t ptr = kdata_base; ptr < offsets.idt; ptr += 4096)
        blacklist_page(&mm, cr3, ptr);
    struct memmap mm_for_linux = {};
    memmap_copy(&mm_for_linux, &mm);
    DBG("done\nChoosing load address... ");
    //avoid loading over 4GB, so that our pointers still work if truncated to 32 bits
    //this does not mean that the kernel itself can't use high memory
    //memmap_add_bad_region(&mm, 0x100000000, -1);
    for(uint64_t i = base; i < addr + linux_size; i += 4096)
        blacklist_page(&mm, cr3, i);
    uint64_t linux_base, linux_area_end;
    uint64_t misalignment = (addr - base) % *(uint32_t*)(addr + 0x230);
    memmap_largest_area(&mm, &linux_base, &linux_area_end, *(uint32_t*)(addr+0x230), misalignment);
    linux_base -= misalignment;
    DBG("done\n");
    if(linux_area_end < linux_base || linux_area_end - linux_base < (addr + linux_size) - base)
        asm volatile("ud2");
    memmap_free(&mm);
    uint64_t persist_offset;
    memcpy(&persist_offset, (void*)(base + 2), sizeof(persist_offset));
    memmap_add_bad_region(&mm_for_linux, linux_base + persist_offset, (linux_base + (uintptr_t)trampoline_end - (uintptr_t)trampoline + 4095) & -4096);
    DBG("Emitting E820... ");
    struct e820_map_entry* dst = (struct e820_map_entry*)(addr + 0x2d0);
    size_t j = memmap_emit_e820(&mm_for_linux, dst, 128);
    for(size_t i = 0; i < sizeof(e820_map) / sizeof(*e820_map) && j < 128; i++)
        if(e820_map[i].type != 1)
            dst[j++] = e820_map[i];
    DBG("done\n");
    *(uint8_t*)(addr+0x1e8) = j;
    *(uint32_t*)(addr+0x218) = initrd_addr + linux_base - base;
    *(uint32_t*)(addr+0xc0) = (initrd_addr + linux_base - base) >> 32;
    *(uint32_t*)(addr+0x21c) = initrd_size;
    *(uint32_t*)(addr+0xc4) = initrd_size >> 32;
    *(uint32_t*)(addr+0x228) = addr + 4096 + linux_base - base;
    *(uint32_t*)(addr+0xc8) = (addr + 4096 + linux_base - base) >> 32;
    uint64_t ref_tsc;
    int64_t ref_secs;
    {
        struct timeval tv = {};
        gettimeofday(&tv, 0);
        uint32_t eax, edx;
        asm volatile("rdtsc":"=a"(eax),"=d"(edx));
        uint64_t tsc = (uint64_t)edx << 32 | eax;
        enum { TSC_FREQ = 1596300166 };
        ref_tsc = tsc - tv.tv_usec * TSC_FREQ / 1000000;
        ref_secs = tv.tv_sec;
    }
    uint64_t trampoline_args[] = {
        linux_base,
        addr + linux_size - base,
        addr + linux_base - base,
        addr + zero_page_size + 512 + linux_base - base,
        ref_tsc,
        ref_secs,
    };
    for(size_t i = 0; i < sizeof(trampoline_args) / sizeof(*trampoline_args); i++)
        memcpy((void*)(base + 10*i + 2), trampoline_args+i, 8);
    DBG("Registering event handler... ");
    r0gdb_kfncall(offsets.eventhandler_register, 0, offsets.s_shutdown_final, offsets.kproc_shutdown, offsets.s_shutdown_final, 0xdeadfb5d00000001, 19999);
    DBG("done\nArming #GP... ");
    uint64_t gp_stack = kmalloc(0x200);
    uint64_t gp_retframe[13] = {offsets.justreturn_pop, 0x20, 2, gp_stack+0x110, 0, 0, 0, virt2phys(pml4_for_linux), offsets.mov_cr3_rax_mov_ds, 0x20, 0x102, 0, 0};
    copyin(gp_stack+0xe8, gp_retframe, sizeof(gp_retframe));
    uint64_t gp_ist = gp_stack + 0x30;
    for(int cpu = 0; cpu < 16; cpu++)
        copyin(offsets.tss_array+0x68*cpu+0x54, &gp_ist, 8);
    char idt_entry[16] = {};
    copyin(offsets.idt+240*16, idt_entry, 16);
    copyout(idt_entry, offsets.idt+16, 16);
    idt_entry[4] = 7;
    copyin(offsets.idt+13*16, idt_entry, 16);
    memcpy(idt_entry, &base, 2);
    memcpy(idt_entry+6, (char*)&base + 2, 6);
    copyin(offsets.idt+16, idt_entry, 16);
    copyin(r0gdb_get_dmap_base()+0xc0115110, "\x00\x02\x00\x00", 4);
    copyin(kdata_base+0x13522a8, "", 1);
    *(uint64_t*)(pml4_for_linux + 8) &= -5; //clear USER bit, we don't want to trigger SMEP
    DBG("done\n");
#ifdef NDEBUG
#if 0 //uncomment to boot right away without the shutdown dance
    nanosleep((void*)"\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 0);
    asm volatile("wrmsr");
#endif
    kill(1, SIGUSR1);
#endif
    asm volatile("ud2");
    return 0;
}
