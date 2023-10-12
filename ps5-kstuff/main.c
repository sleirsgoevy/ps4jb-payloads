#define sysctl __sysctl
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"
#include "../gdb_stub/dbg.h"
#include "uelf/structs.h"
#include "uelf/parasite_desc.h"

void* dlsym(void*, const char*);

void notify(const char* s)
{
    struct
    {
        char pad1[0x10];
        int f1;
        char pad2[0x19];
        char msg[0xc03];
    } notification = {.f1 = -1};
    char* d = notification.msg;
    while(*d++ = *s++);
    ((void(*)())dlsym((void*)0x2001, "sceKernelSendNotificationRequest"))(0, &notification, 0xc30, 0);
}

void die(int line)
{
    char buf[64] = "problem encountered on main.c line ";
    char* p = buf;
    while(*p)
        p++;
    int q = 1;
    while(line / 10 > q)
        q *= 10;
    while(q)
    {
        *p++ = '0' + (line / q) % 10;
        q /= 10;
    }
    notify(buf);
    asm volatile("ud2");
}

#define die() die(__LINE__)

extern uint64_t kdata_base;

void kmemcpy(void* dst, const void* src, size_t sz);

static void kpoke64(void* dst, uint64_t src)
{
    kmemcpy(dst, &src, 8);
}

static void kmemzero(void* dst, size_t sz)
{
    char* umem = mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    mlock(umem, sz);
    kmemcpy(dst, umem, sz);
    munmap(umem, sz);
}

static int strcmp(const char* a, const char* b)
{
    while(*a && *a == *b)
    {
        a++;
        b++;
    }
    return *a - *b;
}

#define kmalloc my_kmalloc

static uint64_t mem_blocks[8];

static void* kmalloc(size_t sz)
{
    for(int i = 0; i < 8; i += 2)
    {
        if(mem_blocks[i] + sz <= mem_blocks[i+1])
        {
            uint64_t ans = mem_blocks[i];
            mem_blocks[i] += sz;
            return (void*)ans;
        }
    }
    die();
    return 0;
}

#define NCPUS 16
#define IDT (offsets.idt)
#define GDT(i) (offsets.gdt_array+0x68*(i))
#define TSS(i) (offsets.tss_array+0x68*(i))
#define PCPU(i) (offsets.pcpu_array+0x900*(i))

size_t virt2file(uint64_t* phdr, uint16_t phnum, uintptr_t addr)
{
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] != 1)
            continue;
        if(h[2] <= addr && h[2] + h[4] > addr)
            return addr + h[1] - h[2];
    }
    return -1;
}

void* load_kelf(void* ehdr, const char** symbols, uint64_t* values, void** base, void** entry, uint64_t mapped_kptr)
{
    uint64_t* phdr = (void*)((char*)ehdr + *(uint64_t*)((char*)ehdr + 32));
    uint16_t phnum = *(uint16_t*)((char*)ehdr + 56);
    uint64_t* dynamic = 0;
    size_t sz_dynamic = 0;
    uint64_t kernel_size = 0;
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] == 2)
        {
            dynamic = (void*)((char*)ehdr + h[1]);
            sz_dynamic = h[4];
        }
        else if((uint32_t)h[0] == 1)
        {
            uint64_t limit = h[2] + h[5];
            if(limit > kernel_size)
                kernel_size = limit;
        }
    }
    kernel_size = ((kernel_size + 4095) | 4095) - 4095;
    char* kptr = kmalloc(kernel_size+4096);
    kptr = (char*)((((uint64_t)kptr - 1) | 4095) + 1);
    if(!mapped_kptr)
        mapped_kptr = (uint64_t)kptr;
    base[0] = kptr;
    base[1] = kptr + kernel_size;
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] != 1)
            continue;
        kmemcpy(kptr+h[2], (char*)ehdr + h[1], h[4]);
        kmemzero(kptr+h[2]+h[4], h[5]-h[4]);
    }
    char* strtab = 0;
    uint64_t* symtab = 0;
    uint64_t* rela = 0;
    size_t relasz = 0;
    for(size_t i = 0; i < sz_dynamic / 16; i++)
    {
        uint64_t* kv = dynamic + 2*i;
        if(kv[0] == 5)
            strtab = (char*)ehdr + virt2file(phdr, phnum, kv[1]);
        else if(kv[0] == 6)
            symtab = (void*)((char*)ehdr + virt2file(phdr, phnum, kv[1]));
        else if(kv[0] == 7)
            rela = (void*)((char*)ehdr + virt2file(phdr, phnum, kv[1]));
        else if(kv[0] == 8)
            relasz = kv[1];
    }
    for(size_t i = 0; i < relasz / 24; i++)
    {
        uint64_t* oia = rela + 3*i;
        if((uint32_t)oia[1] == 1 || (uint32_t)oia[1] == 6)
        {
            uint64_t* sym = symtab + 3 * (oia[1] >> 32);
            const char* name = strtab + (uint32_t)sym[0];
            uint64_t value = sym[1];
            if(!value)
            {
                for(size_t i = 0; symbols[i]; i++)
                    if(!strcmp(symbols[i], name))
                        sym[1] = value = values[i];
                    else if(symbols[i][0] == '.' && !strcmp(symbols[i]+1, name))
                        value = values[i];
                if(!value)
                    die();
            }
            if((uint32_t)oia[1] == 6 && oia[2])
                die();
            if(oia[0] + 8 > kernel_size)
                die();
            kpoke64(kptr+oia[0], oia[2]+value);
        }
        else if((uint32_t)oia[1] == 8)
        {
            if(oia[0] + 8 > kernel_size)
                die();
            kpoke64(kptr+oia[0], (uint64_t)(mapped_kptr+oia[2]));
        }
        else
            die();
    }
    *entry = kptr + *(uint64_t*)((char*)ehdr + 24);
    return kptr;
}

asm(".section .data\nkek:\n.incbin \"kelf\"\nkek_end:");
extern char kek[];
extern char kek_end[];

asm(".section .data\nuek:\n.incbin \"uelf/uelf.bin\"\nuek_end:");
extern char uek[];
extern char uek_end[];

asm(".section .text\nkekcall:\nmov 8(%rsp), %rax\njmp *p_kekcall(%rip)");

uint64_t kekcall(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t nr);

#define KEKCALL_GETPPID        0x000000027
#define KEKCALL_READ_DR        0x100000027
#define KEKCALL_WRITE_DR       0x200000027
#define KEKCALL_RDMSR          0x300000027
#define KEKCALL_REMOTE_SYSCALL 0x500000027
#define KEKCALL_CHECK          0xffffffff00000027

void* p_kekcall;

void* malloc(size_t sz)
{
    return mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
}

uint64_t get_dmap_base(void)
{
    uint64_t ptrs[2];
    copyout(ptrs, offsets.kernel_pmap_store+32, sizeof(ptrs));
    return ptrs[0] - ptrs[1];
}

uint64_t virt2phys(uintptr_t addr)
{
    uint64_t dmap = get_dmap_base();
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

uint64_t find_empty_pml4_index(int idx)
{
    uint64_t dmap = get_dmap_base();
    uint64_t cr3 = r0gdb_read_cr3();
    uint64_t pml4[512];
    copyout(pml4, dmap+cr3, 4096);
    for(int i = 256; i < 512; i++)
        if(!pml4[i] && !idx--)
            return i;
}

void build_uelf_cr3(uint64_t uelf_cr3, void* uelf_base[2], uint64_t uelf_virt_base, uint64_t dmap_virt_base)
{
    static char zeros[4096];
    uint64_t dmap = get_dmap_base();
    uint64_t cr3 = r0gdb_read_cr3();
    uint64_t user_start = (uint64_t)uelf_base[0];
    uint64_t user_end = (uint64_t)uelf_base[1];
    if((uelf_virt_base & 0x1fffff) || (dmap_virt_base & ((1ull << 39) - 1)) || user_end - user_start > 0x200000)
        die();
    uint64_t pml4_virt = uelf_cr3;
    copyin(pml4_virt, zeros, 4096);
    kmemcpy((void*)(pml4_virt+2048), (void*)(dmap+cr3+2048), 2048);
    uint64_t pml3_virt = uelf_cr3 + 4096;
    uint64_t pml3_dmap = uelf_cr3 + 16384; //user-accessible direct mapping of physical memory
    copyin(pml4_virt + 8 * ((uelf_virt_base >> 39) & 511), &(uint64_t[1]){virt2phys(pml3_virt) | 7}, 8);
    copyin(pml4_virt + 8 * ((dmap_virt_base >> 39) & 511), &(uint64_t[1]){virt2phys(pml3_dmap) | 7}, 8);
    copyin(pml3_virt, zeros, 4096);
    uint64_t pml2_virt = uelf_cr3 + 8192;
    copyin(pml3_virt + 8 * ((uelf_virt_base >> 30) & 511), &(uint64_t[1]){virt2phys(pml2_virt) | 7}, 8);
    copyin(pml2_virt, zeros, 4096);
    uint64_t pml1_virt = uelf_cr3 + 12288;
    copyin(pml2_virt + 8 * ((uelf_virt_base >> 21) & 511), &(uint64_t[1]){virt2phys(pml1_virt) | 7}, 8);
    copyin(pml1_virt, zeros, 4096);
    for(uint64_t i = 0; i * 4096 + user_start < user_end; i++)
        copyin(pml1_virt+8*i, &(uint64_t[1]){virt2phys(i*4096+user_start) | 7}, 8);
    for(uint64_t i = 0; i < 512; i++)
        copyin(pml3_dmap+8*i, &(uint64_t[1]){(i<<30) | 135}, 8);
}

int find_proc(const char* name)
{
    for(int pid = 1; pid < 1024; pid++)
    {
        size_t sz = 1096;
        int key[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        char buf[1097] = {0};
        sysctl(key, 4, buf, &sz, 0, 0);
        const char* a = buf + 447;
        const char* b = name;
        while(*a && *a++ == *b++);
        if(!*a && !*b)
            return pid;
    }
    return -1;
}

static uint64_t remote_syscall(int pid, int nr, ...)
{
    va_list va;
    va_start(va, nr);
    uint64_t args[6];
    for(int i = 0; i < 6; i++)
        args[i] = va_arg(va, uint64_t);
    va_end(va);
    return kekcall(pid, nr, (uint64_t)args, 0, 0, 0, KEKCALL_REMOTE_SYSCALL);
}

#define SYS_mdbg_call 573
#define SYS_dynlib_get_info_ex 608

struct module_segment
{
    uint64_t addr;
    uint32_t size;
    uint32_t flags;
};

struct module_info_ex
{
    size_t st_size;
    char name[256];
    int id;
    uint32_t tls_index;
    uint64_t tls_init_addr;
    uint32_t tls_init_size;
    uint32_t tls_size;
    uint32_t tls_offset;
    uint32_t tls_align;
    uint64_t init_proc_addr;
    uint64_t fini_proc_addr;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t eh_frame_hdr_addr;
    uint64_t eh_frame_addr;
    uint32_t eh_frame_hdr_size;
    uint32_t eh_frame_size;
    struct module_segment segments[4];
    uint32_t segment_count;
    uint32_t ref_count;
};

static void patch_shellcore(void)
{
    int pid = find_proc("SceShellCore");
    struct module_info_ex mod_info;
    mod_info.st_size = sizeof(mod_info);
    remote_syscall(pid, SYS_dynlib_get_info_ex, 0, 0, &mod_info);
    uint64_t shellcore_base = mod_info.eh_frame_hdr_addr - 0x13c0000;
    struct
    {
        uint64_t addr;
        void* data;
        size_t sz;
    } patches[] = {
        {shellcore_base+0x974fee, "\x52\xeb\x08\x66\x90", 5},
        {shellcore_base+0x974ff9, "\xe8\xd2\xfb\xff\xff\x58\xc3", 7},
        {shellcore_base+0x974bc1, "\x31\xc0\x50\xeb\xe3", 5},
        {shellcore_base+0x974ba9, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
        {shellcore_base+0x5307f9, "\xeb\x04", 2},
        {shellcore_base+0x26f35c, "\xeb\x04", 2},
        {shellcore_base+0x54e1f0, "\xeb", 1},
        {shellcore_base+0x536e1d, "\x90\xe9", 2},
        {shellcore_base+0x54db8f, "\xeb", 1},
        {shellcore_base+0x55137a, "\xc8\x00\x00\x00", 4},
        {shellcore_base+0x1a12d1, "\xe8\xea\x88\x47\x00\x31\xc9\xff\xc1\xe9\xf4\x02\x00\x00", 14},
        {shellcore_base+0x1a15d3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x29\xfa\xff\xff", 11},
        {shellcore_base+0x1a0fe5, "\xe9\xe7\x02\x00\x00", 5},
    };
    for(int i = 0; i < sizeof(patches) / sizeof(*patches); i++)
    {
        uint64_t arg1[4] = {1, 0x13};
        uint64_t arg2[8] = {pid, patches[i].addr, (uint64_t)patches[i].data, patches[i].sz};
        uint64_t arg3[4] = {0};
        kekcall((uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, 0, 0, 0, SYS_mdbg_call);
    }
}

#ifndef DEBUG
#define dbg_enter()
#define gdb_remote_syscall(...)
#endif

void patch_app_db(void);

static struct PARASITES(13) parasites_403 = {
    .lim_syscall = 3,
    .lim_fself = 11,
    .lim_total = 13,
    .parasites = {
        /* syscall parasites */
        {-0x80284d, RDI},
        {-0x3889ac, RSI},
        {-0x38896c, RSI},
        /* fself parasites */
        {-0x2cc716, RAX},
        {-0x2cd28a, RAX},
        {-0x2cd150, RAX},
        {-0x2cce73, RAX},
        {-0x2ccbfd, RAX},
        {-0x2cc882, RCX},
        {-0x990b10, RDI},
        {-0x2ccd36, R10},
        /* unsorted parasites */
        {-0x479a0e, RAX},
        {-0x479a0e, R15},
    }
};

static struct parasite_desc* get_parasites(size_t* desc_size)
{
    int(*sceKernelGetProsperoSystemSwVersion)(uint32_t*) = dlsym((void*)0x2001, "sceKernelGetProsperoSystemSwVersion");
    uint32_t buf[10];
    sceKernelGetProsperoSystemSwVersion(buf);
    uint32_t ver = buf[9] >> 16;
    switch(ver)
    {
    case 0x403:
        *desc_size = sizeof(parasites_403);
        return (void*)&parasites_403;
    default: return 0;
    }
}

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
    size_t desc_size = 0;
    struct parasite_desc* desc = get_parasites(&desc_size);
    if(!desc)
    {
        notify("your firmware is not supported");
        return 1;
    }
    uint64_t percpu_ist4[NCPUS];
    for(int cpu = 0; cpu < NCPUS; cpu++)
        copyout(&percpu_ist4[cpu], TSS(cpu)+28+4*8, 8);
    uint64_t int1_handler;
    copyout(&int1_handler, IDT+16*1, 2);
    copyout((char*)&int1_handler + 2, IDT+16*1+6, 6);
    uint64_t int13_handler;
    copyout(&int13_handler, IDT+16*13, 2);
    copyout((char*)&int13_handler + 2, IDT+16*13+6, 6);
    dbg_enter();
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"allocating kernel memory... ", (uintptr_t)28);
    for(int i = 0; i < 0x300; i += 2)
        r0gdb_kmalloc(0x100);
    for(int i = 0; i < 2; i += 2)
    {
        while(!mem_blocks[i])
            mem_blocks[i] = r0gdb_kmalloc(1<<23);
        mem_blocks[i+1] = (mem_blocks[i] ? mem_blocks[i] + (1<<23) : 0);
    }
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
    uint64_t shared_area = (uint64_t)kmalloc(8192);
    shared_area = ((shared_area - 1) | 4095) + 1;
    kmemzero((void*)shared_area, 4096);
    uint64_t uelf_virt_base = (find_empty_pml4_index(0) << 39) | (-1ull << 48);
    uint64_t dmem_virt_base = (find_empty_pml4_index(1) << 39) | (-1ull << 48);
    shared_area = virt2phys(shared_area) + dmem_virt_base;
    uint64_t uelf_parasite_desc = (uint64_t)kmalloc(8192);
    uelf_parasite_desc = ((uelf_parasite_desc - 1) | 4095) + 1;
    for(int i = 0; i < desc->lim_total; i++)
        desc->parasites[i].address += kdata_base;
    kmemcpy((void*)uelf_parasite_desc, desc, desc_size);
    uelf_parasite_desc = virt2phys(uelf_parasite_desc) + dmem_virt_base;
    volatile int zero = 0; //hack to force runtime calculation of string pointers
    const char* symbols[] = {
        "dmem"+zero,
        "parasites"+zero,
        "int1_handler"+zero,
        "int13_handler"+zero,
        ".ist_errc"+zero,
        ".ist_noerrc"+zero,
        ".ist4"+zero,
        ".pcpu"+zero,
        "shared_area"+zero,
        ".tss"+zero,
        ".uelf_cr3"+zero,
        ".uelf_entry"+zero,
#define OFFSET(x) (#x)+zero,
#include "../prosper0gdb/offset_list.txt"
#undef OFFSET
        0,
    };
    uint64_t values[] = {
        dmem_virt_base,        // dmem
        uelf_parasite_desc,    // parasites
        int1_handler,          // int1_handler
        int13_handler,         // int13_handler
        0x1237,                // .ist_errc
        0x1238,                // .ist_noerrc
        0x1239,                // .ist4
        0x1234,                // .pcpu
        shared_area, // shared_area
        0x123a,                // .tss
        0x1235,                // .uelf_cr3
        0x1236,                // .uelf_entry
#define OFFSET(x) offsets.x,
#include "../prosper0gdb/offset_list.txt"
#undef OFFSET
        0,
    };
    size_t pcpu_idx, uelf_cr3_idx, uelf_entry_idx, ist_errc_idx, ist_noerrc_idx, ist4_idx, tss_idx;
    for(size_t i = 0; values[i]; i++)
        switch(values[i])
        {
        case 0x1234: pcpu_idx = i; break;
        case 0x1235: uelf_cr3_idx = i; break;
        case 0x1236: uelf_entry_idx = i; break;
        case 0x1237: ist_errc_idx = i; break;
        case 0x1238: ist_noerrc_idx = i; break;
        case 0x1239: ist4_idx = i; break;
        case 0x123a: tss_idx = i; break;
        }
    uint64_t uelf_bases[NCPUS];
    uint64_t kelf_bases[NCPUS];
    uint64_t kelf_entries[NCPUS];
    uint64_t uelf_cr3s[NCPUS];
    for(int cpu = 0; cpu < NCPUS; cpu++)
    {
        char buf[] = "loading on cpu ..\n";
        if(cpu >= 10)
        {
            buf[15] = '1';
            buf[16] = (cpu - 10) + '0';
            gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)buf, (uintptr_t)18);
        }
        else
        {
            buf[15] = cpu + '0';
            buf[16] = '\n';
            gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)buf, (uintptr_t)17);
        }
        values[pcpu_idx] = PCPU(cpu);
        values[uelf_cr3_idx] = 0;
        values[uelf_entry_idx] = 0;
        values[ist_errc_idx] = TSS(cpu)+28+3*8;
        values[ist_noerrc_idx] = TSS(cpu)+28+7*8;
        values[ist4_idx] = percpu_ist4[cpu];
        values[tss_idx] = TSS(cpu);
        void* uelf_entry = 0;
        void* uelf_base[2] = {0};
        char* uelf = load_kelf(uek, symbols, values, uelf_base, &uelf_entry, uelf_virt_base);
        uintptr_t uelf_cr3 = (uintptr_t)kmalloc(24576);
        uelf_cr3 = ((uelf_cr3 + 4095) | 4095) - 4095;
        uelf_cr3s[cpu] = uelf_cr3;
        values[uelf_cr3_idx] = virt2phys(uelf_cr3);
        values[uelf_entry_idx] = (uintptr_t)uelf_entry - (uintptr_t)uelf_base[0] + uelf_virt_base;
        void* entry = 0;
        void* base[2] = {0};
        char* kelf = load_kelf(kek, symbols, values, base, &entry, 0);
        build_uelf_cr3(uelf_cr3, uelf_base, uelf_virt_base, dmem_virt_base);
        uelf_bases[cpu] = (uintptr_t)uelf;
        kelf_bases[cpu] = (uint64_t)kelf;
        kelf_entries[cpu] = (uint64_t)entry;
    }
    r0gdb_wrmsr(0xc0000084, r0gdb_rdmsr(0xc0000084) | 0x100);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done loading\npatching idt... ", (uintptr_t)29);
    uint64_t cr3 = r0gdb_read_cr3();
    for(int cpu = 0; cpu < NCPUS; cpu++)
    {
        uint64_t entry = kelf_entries[cpu];
        kmemcpy((char*)IDT+16*13, (char*)entry, 2);
        kmemcpy((char*)IDT+16*13+6, (char*)entry+2, 6);
        kmemcpy((char*)IDT+16*13+4, "\x03", 1);
        kmemcpy((char*)IDT+16*1, (char*)entry+16, 2);
        kmemcpy((char*)IDT+16*1+6, (char*)entry+18, 6);
        kmemcpy((char*)IDT+16*1+4, "\x07", 1);
        kmemcpy((char*)TSS(cpu)+28+3*8, (char*)entry+8, 8);
        kmemcpy((char*)TSS(cpu)+28+7*8, (char*)entry+24, 8);
    }
    uint64_t iret = offsets.doreti_iret;
    kmemcpy((char*)(IDT+16*2), (char*)&iret, 2);
    kmemcpy((char*)(IDT+16*2+6), (char*)&iret+2, 6);
    //kmemzero((char*)(IDT+16*1), 16);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\napplying kdata patches... ", (uintptr_t)31);
    copyin(offsets.sysentvec + 14, &(const uint16_t[1]){0xdeb7}, 2); //native sysentvec
    copyin(offsets.sysentvec_ps4 + 14, &(const uint16_t[1]){0xdeb7}, 2); //ps4 sysentvec
    copyin(offsets.crypt_singleton_array + 11*8 + 2*8 + 6, &(const uint16_t[1]){0xdeb7}, 2); //crypt xts
    copyin(offsets.crypt_singleton_array + 11*8 + 9*8 + 6, &(const uint16_t[1]){0xdeb7}, 2); //crypt hmac
    {
        //enable debug settings & spoof target
        uint32_t q = 0;
        copyout(&q, offsets.security_flags, 4);
        q |= 0x14;
        copyin(offsets.security_flags, &q, 4);
        copyin(offsets.targetid, "\x82", 1);
        copyout(&q, offsets.qa_flags, 4);
        q |= 0x1030300;
        copyin(offsets.qa_flags, &q, 4);
        copyout(&q, offsets.utoken, 4);
        q |= 1;
        copyin(offsets.utoken, &q, 4);
    }
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\npatching shellcore... ", (uintptr_t)27);
    p_kekcall = (char*)dlsym((void*)0x2001, "getpid") + 7;
    //restore the gdb_stub's SIGTRAP handler
    struct sigaction sa;
    sigaction(SIGBUS, 0, &sa);
    sigaction(SIGTRAP, &sa, 0);
    sigaction(SIGPIPE, &sa, 0);
    copyin(IDT+16*9+5, "\x8e", 1);
    copyin(IDT+16*179+5, "\x8e", 1);
    patch_shellcore();
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\npatching app.db... ", (uintptr_t)24);
    patch_app_db();
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
#ifndef DEBUG
    notify("ps5-kstuff successfully loaded");
    return 0;
#endif
    asm volatile("ud2");
    return 0;
}
