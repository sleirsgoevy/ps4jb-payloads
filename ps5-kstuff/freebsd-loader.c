#define _BSD_SOURCE
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

void kkfncall(void* td, uintptr_t** uap)
{
    uap[1][0] = ((uintptr_t(*)())uap[1][0])(uap[1][1], uap[1][2], uap[1][3], uap[1][4], uap[1][5], uap[1][6], uap[1][7]);
}

uintptr_t kfncall(uintptr_t fn, ...)
{
    uintptr_t args[7] = {fn};
    va_list va;
    va_start(va, fn);
    for(int i = 0; i < 6; i++)
        args[i+1] = va_arg(va, uintptr_t);
    va_end(va);
    syscall(11, kkfncall, args);
    return args[0];
}

void kmemcpy(void* dst, const void* src, size_t sz)
{
    kfncall(0xffffffff80f9e760, (uintptr_t)dst, (uintptr_t)src, (uintptr_t)sz);
}

void kpoke64(void* dst, uint64_t value)
{
    kmemcpy(dst, &value, 8);
}

void kmemzero(void* dst, size_t sz)
{
    kfncall(0xffffffff810c4b40, (uintptr_t)dst, 0, sz);
}

void copyout(void* dst, uintptr_t src, size_t sz)
{
    kfncall(0xffffffff80f9e800, src, (uintptr_t)dst, sz);
}

void copyin(uintptr_t dst, const void* src, size_t sz)
{
    kfncall(0xffffffff80f9e880, (uintptr_t)src, dst, sz);
}

void* kmalloc(size_t sz)
{
    return (void*)kfncall(0xffffffff80aaf760, sz, 0xffffffff819b3e90, 2);
}

void krcr3(void* td, uint64_t** uap)
{
    asm volatile("mov %%cr3, %0":"=r"(uap[1][0]));
}

uint64_t r0gdb_read_cr3(void)
{
    uint64_t cr3;
    syscall(11, krcr3, &cr3);
    return cr3;
}

#define NCPUS 3
#define IDT 0xffffffff81d7d540
#define GDT(i) (0xffffffff81e2a7d0+0x68*(i))
#define TSS(i) (0xffffffff81e23f90+0x68*(i))
#define PCPU(i) (0xffffffff81e31080+0x400*(i))

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
                    asm volatile("ud2");
            }
            if((uint32_t)oia[1] == 6 && oia[2])
                asm volatile("ud2");
            kpoke64(kptr+oia[0], oia[2]+value);
        }
        else if((uint32_t)oia[1] == 8)
            kpoke64(kptr+oia[0], (uint64_t)(mapped_kptr+oia[2]));
        else
            asm volatile("ud2");
    }
    *entry = kptr + *(uint64_t*)((char*)ehdr + 24);
    return kptr;
}

asm(".section .data\nkek:\n.incbin \"kelf\"\nkek_end:");
extern char kek[];
extern char kek_end[];

asm(".section .data\nuek:\n.incbin \"uelf/uelf\"\nuek_end:");
extern char uek[];
extern char uek_end[];

asm(".section .text\nkekcall:\nmov 8(%rsp), %rax\njmp *p_kekcall(%rip)");

int kekcall(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t nr);

#define KEKCALL_GETPPID  0x000000027
#define KEKCALL_READ_DR  0x100000027
#define KEKCALL_WRITE_DR 0x200000027

void* p_kekcall;
void* dlsym(void*, const char*);

void* malloc(size_t sz)
{
    return mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
}

uint64_t get_dmap_base(void)
{
    uint64_t ptrs[2];
    copyout(ptrs, 0xffffffff81e71920, sizeof(ptrs));
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

void build_uelf_cr3(uint64_t uelf_cr3, void* uelf_base[2])
{
    static char zeros[4096];
    uint64_t dmap = get_dmap_base();
    uint64_t cr3 = r0gdb_read_cr3();
    uint64_t user_start = (uint64_t)uelf_base[0];
    uint64_t user_end = (uint64_t)uelf_base[1];
    if(user_end - user_start > 0x200000)
        asm volatile("ud2");
    uint64_t pml4_virt = uelf_cr3;
    copyin(pml4_virt, zeros, 4096);
    kmemcpy((void*)(pml4_virt+2048), (void*)(dmap+cr3+2048), 2048);
    uint64_t pml3_virt = uelf_cr3 + 4096;
    uint64_t pml3_dmap = uelf_cr3 + 16384; //user-accessible direct mapping of physical memory
    copyin(pml4_virt, &(uint64_t[2]){virt2phys(pml3_virt) | 7, virt2phys(pml3_dmap) | 7}, 16);
    copyin(pml3_virt, zeros, 4096);
    uint64_t pml2_virt = uelf_cr3 + 8192;
    copyin(pml3_virt, &(uint64_t[1]){virt2phys(pml2_virt) | 7}, 8);
    copyin(pml2_virt, zeros, 4096);
    uint64_t pml1_virt = uelf_cr3 + 12288;
    copyin(pml2_virt+16, &(uint64_t[1]){virt2phys(pml1_virt) | 7}, 8);
    copyin(pml1_virt, zeros, 4096);
    for(uint64_t i = 0; i * 4096 + user_start < user_end; i++)
        copyin(pml1_virt+8*i, &(uint64_t[1]){virt2phys(i*4096+user_start) | 7}, 8);
    for(uint64_t i = 0; i < 512; i++)
        copyin(pml3_dmap+8*i, &(uint64_t[1]){(i<<30) | 135}, 8);
}

int main()
{
    mlock(kek, kek_end-kek);
    mlock(uek, uek_end-uek);
    const char* symbols[] = {
        "add_rsp_iret",
        "copyin",
        "copyout",
        "doreti_iret",
        "dr2gpr_start",
        "gpr2dr_1_start",
        "gpr2dr_2_start",
        "justreturn",
        "justreturn_pop",
        ".ist_errc",
        ".ist_noerrc",
        "mov_cr3_rax",
        "mov_rdi_cr3",
        "nop_ret",
        ".pcpu",
        "pop_all_iret",
        "push_pop_all_iret",
        "rdmsr_start",
        "rep_movsb_pop_rbp_ret",
        "swapgs_add_rsp_iret",
        "syscall_after",
        "syscall_before",
        "sysents",
        ".uelf_cr3",
        ".uelf_entry",
        "wrmsr_ret",
        0,
    };
    uint64_t values[] = {
        0xffffffff80f8568d, // add_rsp_iret
        0xffffffff80f9e880, // copyin
        0xffffffff80f9e800, // copyout
        0xffffffff80f85695, // doreti_iret
        0xffffffff80f837a8, // dr2gpr_start
        0xffffffff80f8381e, // gpr2dr_1_start
        0xffffffff802ffeba, // gpr2dr_2_start
        0xffffffff80f85550, // justreturn
        0xffffffff80f85558, // justreturn_pop
        0x1237,    // ist_errc
        0x1238,    // ist_noerrc
        0xffffffff80f82d87, // mov_cr3_rax
        0xffffffff80cc27ed, // mov_rdi_cr3
        0xffffffff802ff132, // nop_ret
        0x1234,             // .pcpu
        0xffffffff80f85636, // pop_all_iret
        0xffffffff80f84f80, // push_pop_all_iret
        0xffffffff80f81f53, // rdmsr_start
        0xffffffff80f9e779, // rep_movsb_pop_rbp_ret
        0xffffffff80f8568b, // swapgs_add_rsp_iret, XXX
        0xffffffff80fa168e, // syscall_after
        0xffffffff80fa168b, // syscall_before
        0xffffffff819a7840, // sysents
        0x1235,             // .uelf_cr3
        0x1236,             // .uelf_entry
        0xffffffff80f84756, // wrmsr_ret
        0,
    };
    size_t pcpu_idx, uelf_cr3_idx, uelf_entry_idx, ist_errc_idx, ist_noerrc_idx;
    for(size_t i = 0; values[i]; i++)
        switch(values[i])
        {
        case 0x1234: pcpu_idx = i; break;
        case 0x1235: uelf_cr3_idx = i; break;
        case 0x1236: uelf_entry_idx = i; break;
        case 0x1237: ist_errc_idx = i; break;
        case 0x1238: ist_noerrc_idx = i; break;
        }
    uint64_t uelf_bases[NCPUS];
    uint64_t kelf_bases[NCPUS];
    uint64_t kelf_entries[NCPUS];
    for(int cpu = 0; cpu < NCPUS; cpu++)
    {
        values[pcpu_idx] = PCPU(cpu);
        values[uelf_cr3_idx] = 0;
        values[uelf_entry_idx] = 0;
        values[ist_errc_idx] = TSS(cpu)+28+3*8;
        values[ist_noerrc_idx] = TSS(cpu)+28+7*8;
        void* uelf_entry = 0;
        void* uelf_base[2] = {0};
        char* uelf = load_kelf(uek, symbols, values, uelf_base, &uelf_entry, 0x400000);
        uintptr_t uelf_cr3 = (uintptr_t)kmalloc(24576);
        uelf_cr3 = ((uelf_cr3 + 4095) | 4095) - 4095;
        values[uelf_cr3_idx] = virt2phys(uelf_cr3);
        values[uelf_entry_idx] = (uintptr_t)uelf_entry - (uintptr_t)uelf_base[0] + 0x400000;
        void* entry = 0;
        void* base[2] = {0};
        char* kelf = load_kelf(kek, symbols, values, base, &entry, 0);
        build_uelf_cr3(uelf_cr3, uelf_base);
        uelf_bases[cpu] = (uintptr_t)uelf;
        kelf_bases[cpu] = (uint64_t)kelf;
        kelf_entries[cpu] = (uint64_t)entry;
    }
    uint64_t cr3 = r0gdb_read_cr3();
    for(int cpu = 0; cpu < NCPUS; cpu++)
    {
        uint64_t entry = kelf_entries[cpu];
        kmemcpy((char*)IDT+16*13, (char*)entry, 2);
        kmemcpy((char*)IDT+16*13+6, (char*)entry+2, 6);
        kmemcpy((char*)IDT+16*13+4, "\x03", 1);
        kmemcpy((char*)IDT+16*0x7c, (char*)entry+16, 2);
        kmemcpy((char*)IDT+16*0x7c+6, (char*)entry+18, 6);
        kmemcpy((char*)IDT+16*0x7c+4, "\x07\xee", 2);
        kmemcpy((char*)IDT+16*1, (char*)entry+16, 2);
        kmemcpy((char*)IDT+16*1+6, (char*)entry+18, 6);
        kmemcpy((char*)IDT+16*1+4, "\x07", 1);
        kmemcpy((char*)TSS(cpu)+28+3*8, (char*)entry+8, 8);
        kmemcpy((char*)TSS(cpu)+28+7*8, (char*)entry+24, 8);
    }
    //kmemzero((char*)IDT+16*1, 16);
    uint64_t iret = 0xffffffff80f85695;
    kmemcpy((char*)(IDT+16*2), (char*)&iret, 2);
    kmemcpy((char*)(IDT+16*2+6), (char*)&iret+2, 6);
    return 0;
}
