#include <sys/types.h>
#include <sys/mman.h>
#include "../prosper0gdb/r0gdb.h"
#include "../gdb_stub/dbg.h"

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
    asm volatile("ud2");
    return 0;
}

#define NCPUS 16
#define IDT (kdata_base+0x64cdc80)
#define TSS(i) (kdata_base+0x64d0830+0x68*(i))

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

void* load_kelf(void* ehdr, const char** symbols, uint64_t* values, void** entry)
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
    char* kptr = kmalloc(kernel_size+65536);
    kptr = (char*)((((uint64_t)kptr - 1) | 65535) + 1);
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
        if((uint32_t)oia[1] == 1)
        {
            uint64_t* sym = symtab + 3 * (oia[1] >> 32);
            const char* name = strtab + (uint32_t)sym[0];
            if(!sym[1])
            {
                for(size_t i = 0; symbols[i]; i++)
                    if(!strcmp(symbols[i], name))
                        sym[1] = values[i];
                if(!sym[1])
                    asm volatile("ud2");
            }
            kpoke64(kptr+oia[0], oia[2]+sym[1]);
        }
        else if((uint32_t)oia[1] == 8)
            kpoke64(kptr+oia[0], (uint64_t)(kptr+oia[2]));
    }
    *entry = kptr + *(uint64_t*)((char*)ehdr + 24);
    return kptr;
}

asm("kek:\n.incbin \"kek\"\nkek_end:");
extern char kek[];
extern char kek_end[];

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
    dbg_enter();
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"allocating memory... ", (uintptr_t)21);
    for(int i = 0; i < 4; i += 2)
    {
        mem_blocks[i] = r0gdb_kmalloc(1<<24);
        mem_blocks[i+1] = mem_blocks[i] + (1<<24);
    }
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
    const char* symbols[] = {
        "add_rsp_iret",
        "doreti_iret",
        "kdata_base",
        "pop_all_iret",
        "push_pop_all_iret",
        "rep_movsb_pop_rbp_ret",
        "syscall_after",
        "syscall_before",
        "sysents",
        0,
    };
    uint64_t values[] = {
        kdata_base - 0x9cf853,
        kdata_base - 0x9cf84c,
        kdata_base,
        kdata_base - 0x9cf8ab,
        kdata_base - 0x96be70,
        kdata_base - 0x990a55,
        kdata_base - 0x8022ee,
        kdata_base - 0x802311,
        kdata_base + 0x1709c0,
        0,
    };
    char* mem = mmap(0, kek_end-kek, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    mlock(mem, kek_end-kek);
    char* p_mem = mem;
    for(char* p_kek = kek; p_kek != kek_end; p_kek++)
        *p_mem++ = *p_kek;
    uint64_t kelf_bases[NCPUS];
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
        void* entry = 0;
        char* kelf = load_kelf(mem, symbols, values, &entry);
        kelf_bases[cpu] = (uint64_t)kelf;
        kmemcpy((char*)IDT+16*13, (char*)entry, 2);
        kmemcpy((char*)IDT+16*13+6, (char*)entry+2, 6);
        kmemcpy((char*)IDT+16*13+4, "\3", 1);
        kmemcpy((char*)TSS(cpu)+28+3*8, (char*)entry+8, 8);
    }
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done loading\npatching sysentvec... ", (uintptr_t)35);
    copyin(kdata_base + 0xd11bb8 + 14, &(const uint16_t[1]){0xdeb7}, 2);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
    asm volatile("ud2");
    return 0;
}
