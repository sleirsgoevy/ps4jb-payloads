#include <sys/shm.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <kenv.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"
#include "../gdb_stub/dbg.h"

asm(".p2align 3\nfakexen_start:\n.incbin \"fakexen/fakexen.elf\"\nfakexen_end:");

extern char fakexen_start[];
extern char fakexen_end[];
extern char trampoline_start[];
extern char trampoline_end[];

static int strcmp(const char* a, const char* b)
{
    while(*a && *a == *b)
    {
        a++;
        b++;
    }
    return *a - *b;
}

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

uint64_t create_cr3(size_t npages)
{
    uint64_t dmap = r0gdb_get_dmap_base();
    uint64_t cr3 = alloc_page();
    uint64_t dmem1 = alloc_page();
    uint64_t dmem2 = alloc_page();
    uint64_t page[512] = {dmem1 | 7, dmem2 | 7};
    copyout(page+256, dmap+r0gdb_read_cr3()+2048, 2048);
    copyin(dmap+cr3, page, sizeof(page));
    for(size_t i = 0; i < 512; i++)
        page[i] = (i << 30) | 135;
    copyin(dmap+dmem1, page, sizeof(page));
    for(size_t i = 0; i < 512; i++)
        page[i] = (i << 30) | 159;
    copyin(dmap+dmem2, page, sizeof(page));
    for(uint64_t virt = 2ull << 39; virt < (2ull << 39) + (npages << 12); virt += 4096)
        map_page(cr3, virt);
    return cr3;
}

struct
{
    uint64_t start;
    uint64_t size;
    uint32_t type;
} __attribute__((packed)) e820_map[] = {
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

void in_al(void)
{
    asm volatile("in $0x61, %%al":::"eax");
}

static void receive_linux(char** p_p, size_t* p_sz)
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
        int fd = open("/user/vmlinux", O_RDONLY);
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
        int fd = open("/user/vmlinux", O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(fd >= 0)
        {
            write(fd, addr, size);
            close(fd);
        }
    }
    *p_p = addr;
    *p_sz = size;
}

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

asm("kekcall:\nmov 8(%rsp), %rax\njmp *p_syscall(%rip)");

uint64_t kekcall(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    if(r0gdb_init(ds, a, b, c, d))
        return 1;
    if(!kekcall(0, 0, 0, 0, 0, 0, 0xffffffff00000027))
        asm volatile("ud2");
    //dbg_enter();
    r0gdb_setup(0);
    char* linux_start;
    size_t linux_size;
    receive_linux(&linux_start, &linux_size);
    uint64_t* ehdr = (uint64_t*)fakexen_start;
    uint64_t phoff = ehdr[4];
    uint16_t phnum = ehdr[7];
    uint64_t max_addr = 0;
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* phdr = (uint64_t*)(fakexen_start + phoff + 56 * i);
        if((uint32_t)phdr[0] == 1 && max_addr < phdr[2] + phdr[5])
            max_addr = phdr[2] + phdr[5];
    }
    max_addr = (max_addr + 4095) & -4096;
    uint64_t linux_linear_start = max_addr;
    uint64_t linux_linear_end = max_addr + linux_size;
    uint64_t e820_linear_start = linux_linear_end;
    uint64_t e820_linear_end = e820_linear_start + sizeof(e820_map);
    size_t npages = (e820_linear_end + 4095) >> 12;
    uint64_t trampoline_page = npages << 12;
    npages++;
    uint64_t cr3 = create_cr3(npages);
    uint64_t pml3_2;
    copyout(&pml3_2, r0gdb_get_dmap_base()+cr3+16, 8);
    copyin(r0gdb_get_dmap_base()+r0gdb_read_cr3()+16, &pml3_2, 8);
    char* mapping = (char*)(2ull << 39);
    enum { VIRTUAL_BASE = 0xffff810000000000 };
    uint64_t* dynamic_start = 0;
    uint64_t* dynamic_end = 0;
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* phdr = (uint64_t*)(fakexen_start + phoff + 56 * i);
        if((uint32_t)phdr[0] == 1)
        {
            uint64_t offset = phdr[1];
            uint64_t vaddr = phdr[2];
            uint64_t filesz = phdr[4];
            uint64_t memsz = phdr[5];
            char* dst = mapping + vaddr;
            char* src = fakexen_start + offset;
            for(size_t i = 0; i < filesz; i++)
                dst[i] = src[i];
            for(size_t i = filesz; i < memsz; i++)
                dst[i] = 0;
        }
        else if((uint32_t)phdr[0] == 2)
        {
            uint64_t offset = phdr[1];
            uint64_t filesz = phdr[4];
            dynamic_start = (uint64_t*)(fakexen_start + offset);
            dynamic_end = (uint64_t*)(fakexen_start + offset + filesz);
        }
    }
    volatile int zero = 0;
    const char* symbols[] = {
        "image_start",
        "linux_start",
        "linux_end",
        "e820_start",
        "e820_end",
        "image_end",
        "kdata_base",
        "acpi_rsdp",
#define OFFSET(x) (#x)+zero,
#include "../prosper0gdb/offset_list.txt"
#undef OFFSET
        0,
    };
    uint64_t symbol_values[] = {
        VIRTUAL_BASE,
        VIRTUAL_BASE+linux_linear_start,
        VIRTUAL_BASE+linux_linear_end,
        VIRTUAL_BASE+e820_linear_start,
        VIRTUAL_BASE+e820_linear_end,
        VIRTUAL_BASE+e820_linear_end,
        kdata_base,
        get_acpi_rsdp(),
#define OFFSET(x) offsets.x,
#include "../prosper0gdb/offset_list.txt"
#undef OFFSET
        0,
    };
    char* strtab = 0;
    uint64_t* symtab = 0;
    uint64_t* rela = 0;
    size_t relasz = 0;
    for(uint64_t* kv = dynamic_start; kv + 1 < dynamic_end; kv += 2)
    {
        if(kv[0] == 5)
            strtab = mapping + kv[1];
        else if(kv[0] == 6)
            symtab = (uint64_t*)(mapping + kv[1]);
        else if(kv[0] == 7)
            rela = (uint64_t*)(mapping + kv[1]);
        else if(kv[0] == 8)
            relasz = kv[1];
    }
    uint64_t* rela_end = (uint64_t*)((uint64_t)rela + relasz);
    for(uint64_t* oia = rela; oia + 2 < rela_end; oia += 3)
    {
        if((uint32_t)oia[1] == 1 || (uint32_t)oia[1] == 6)
        {
            uint64_t* sym = symtab + 3 * (oia[1] >> 32);
            const char* name = strtab + (uint32_t)sym[0];
            uint64_t value = sym[1];
            if(!value)
            {
                for(size_t i = 0; symbols[i]; i++)
                    if(!strcmp(symbols[i], name))
                        sym[1] = value = symbol_values[i];
                if(!value)
                    asm volatile("ud2");
            }
            if((uint32_t)oia[1] == 6 && oia[2])
                asm volatile("ud2");
            if(oia[0] + 8 > max_addr)
                asm volatile("ud2");
            *(uint64_t*)(mapping + oia[0]) = value;
        }
        else if((uint32_t)oia[1] == 8)
        {
            if(oia[0] + 8 > max_addr)
                asm volatile("ud2");
            *(uint64_t*)(mapping + oia[0]) = VIRTUAL_BASE + oia[2];
        }
        else
            asm volatile("ud2");
    }
    {
        char* dst = mapping + linux_linear_start;
        for(size_t i = 0; i < linux_size; i++)
            dst[i] = linux_start[i];
        dst = mapping + e820_linear_start;
        char* src = (char*)&e820_map;
        for(size_t i = 0; i < sizeof(e820_map); i++)
            dst[i] = src[i];
    }
    uint64_t entry = VIRTUAL_BASE + ehdr[3];
    {
        char* dst = mapping + trampoline_page;
        for(char* src = trampoline_start; src < trampoline_end; src++)
            *dst++ = *src;
        uint64_t args[3] = {cr3, entry - 0xffff800000000000, r0gdb_rdmsr(0x1b) & -4096};
        for(size_t i = 0; i < 3; i++)
            *(uint64_t*)(mapping + trampoline_page + 10*i + 2) = args[i];
    }
    uint64_t trampoline_phys = virt2phys((uint64_t)(mapping + trampoline_page));
    r0gdb_kfncall(offsets.eventhandler_register, 0, offsets.s_shutdown_final, offsets.kproc_shutdown, offsets.s_shutdown_final, 0xdeadfb5d00000001, 19999);
    uint64_t int1_stack = kmalloc(0x200);
    uint64_t int1_retframe[5] = {trampoline_phys, 0x43, 2, 0, 0x3b};
    copyin(int1_stack + 0xf0, int1_retframe, sizeof(int1_retframe));
    uint64_t int1_ist = int1_stack + 0x30;
    uint64_t gp_stack = kmalloc(0x200);
    uint64_t gp_retframe[13] = {offsets.justreturn_pop, 0x20, 2, gp_stack+0x110, 0, 0, 0, cr3, offsets.mov_cr3_rax_mov_ds, 0x20, 0x102, 0, 0};
    copyin(gp_stack + 0xe8, gp_retframe, sizeof(gp_retframe));
    uint64_t gp_ist = gp_stack + 0x30;
    for(int cpu = 0; cpu < 16; cpu++)
    {
        copyin(offsets.tss_array+0x68*cpu+0x3c, &int1_ist, 8);
        copyin(offsets.tss_array+0x68*cpu+0x54, &gp_ist, 8);
        copyin(offsets.idt+13*16+4, "\x07", 1);
    }
    char idt_entry[16] = {};
    copyin(offsets.idt+240*16, idt_entry, 16);
    copyout(idt_entry, offsets.idt+16, 16);
    idt_entry[4] = 7;
    copyin(offsets.idt+13*16, idt_entry, 16);
    copyin(r0gdb_get_dmap_base()+0xc0115110, "\x00\x02\x00\x00", 4);
    copyin(kdata_base+0x13522a8, "", 1);
    //asm volatile("wrmsr"); //uncomment to jump to fakexen directly without cleanly rebooting
    kill(1, SIGUSR1);
    asm volatile("ud2");
    return 0;
}
