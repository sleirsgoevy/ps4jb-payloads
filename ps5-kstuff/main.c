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
#define PCPU(i) (kdata_base+0x64d2280+0x900*(i))

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
            kpoke64(kptr+oia[0], oia[2]+value);
        }
        else if((uint32_t)oia[1] == 8)
            kpoke64(kptr+oia[0], (uint64_t)(kptr+oia[2]));
    }
    *entry = kptr + *(uint64_t*)((char*)ehdr + 24);
    return kptr;
}

asm(".section .data\nkek:\n.incbin \"kek\"\nkek_end:");
extern char kek[];
extern char kek_end[];

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

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
    dbg_enter();
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"allocating kernel memory... ", (uintptr_t)28);
    for(int i = 0; i < 8; i += 2)
    {
        while(!mem_blocks[i])
            mem_blocks[i] = r0gdb_kmalloc(1<<24);
        mem_blocks[i+1] = (mem_blocks[i] ? mem_blocks[i] + (1<<24) : 0);
    }
    char* scratchpad = kmalloc(1048576);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
    volatile int zero = 0; //hack to force runtime calculation of string pointers
    const char* symbols[] = {
        "add_rsp_iret"+zero,
        "copyin"+zero,
        "copyout"+zero,
        "decryptSelfBlock_epilogue"+zero,
        "decryptSelfBlock_watchpoint"+zero,
        "decryptSelfBlock_watchpoint_lr"+zero,
        "doreti_iret"+zero,
        "dr2gpr_end"+zero,
        "dr2gpr_start"+zero,
        "gpr2dr_1_end"+zero,
        "gpr2dr_1_start"+zero,
        "gpr2dr_2_end"+zero,
        "gpr2dr_2_start"+zero,
        "kdata_base"+zero,
        "loadSelfSegment_epilogue"+zero,
        "loadSelfSegment_watchpoint"+zero,
        "loadSelfSegment_watchpoint_lr"+zero,
        "mini_syscore_header"+zero,
        ".pcpu"+zero,
        "pop_all_except_rdi_iret"+zero,
        "pop_all_iret"+zero,
        "push_pop_all_iret"+zero,
        "rdmsr_end"+zero,
        "rdmsr_start"+zero,
        "rep_movsb_pop_rbp_ret"+zero,
        "sceSblServiceIsLoadable2"+zero,
        "sceSblServiceMailbox"+zero,
        "sceSblServiceMailbox_lr_decryptSelfBlock"+zero,
        "sceSblServiceMailbox_lr_loadSelfSegment"+zero,
        "sceSblServiceMailbox_lr_verifyHeader"+zero,
        "scratchpad"+zero,
        "soo_ioctl"+zero,
        "syscall_after"+zero,
        "syscall_before"+zero,
        "sysents"+zero,
        0,
    };
    uint64_t values[] = {
        kdata_base - 0x9cf853, // add_rsp_iret
        kdata_base - 0x9908e0, // copyin
        kdata_base - 0x990990, // copyout
        kdata_base - 0x8a52c3, // decryptSelfBlock_epilogue
        kdata_base - 0x2cc88e, // decryptSelfBlock_watchpoint
        kdata_base - 0x8a538a, // decryptSelfBlock_watchpoint_lr
        kdata_base - 0x9cf84c, // doreti_iret
        kdata_base - 0x9d6d7c, // dr2gpr_end
        kdata_base - 0x9d6d93, // dr2gpr_start
        kdata_base - 0x9d6c55, // gpr2dr_1_end
        kdata_base - 0x9d6c7a, // gpr2dr_1_start
        kdata_base - 0x9d6de9, // gpr2dr_2_end
        kdata_base - 0x9d6b87, // gpr2dr_2_start
        kdata_base,            // kdata_base
        kdata_base - 0x8a54cd, // loadSelfSegment_epilogue
        kdata_base - 0x2cc918, // loadSelfSegment_watchpoint
        kdata_base - 0x8a5727, // loadSelfSegment_watchpoint_lr
        kdata_base + 0xdc16e8, // mini_syscore_header
        0x1234,                // .pcpu
        kdata_base - 0x9cf8a7, // pop_all_except_rdi_iret
        kdata_base - 0x9cf8ab, // pop_all_iret
        kdata_base - 0x96be70, // push_pop_all_iret
        kdata_base - 0x9d6cf9, // rdmsr_end
        kdata_base - 0x9d6d02, // rdmsr_start
        kdata_base - 0x990a55, // rep_movsb_pop_rbp_ret
        kdata_base - 0x8a5c40, // sceSblServiceIsLoadable2
        kdata_base - 0x6824c0, // sceSblServiceMailbox
        kdata_base - 0x8a5014, // sceSblServiceMailbox_lr_decryptSelfBlock
        kdata_base - 0x8a5541, // sceSblServiceMailbox_lr_loadSelfSegment
        kdata_base - 0x8a58bc, // sceSblServiceMailbox_lr_verifyHeader
        (uint64_t)scratchpad,  // scratchpad
        kdata_base - 0x96eb98, // soo_ioctl
        kdata_base - 0x8022ee, // syscall_after
        kdata_base - 0x802311, // syscall_before
        kdata_base + 0x1709c0, // sysents
        0,
    };
    size_t pcpu_idx;
    for(pcpu_idx = 0; values[pcpu_idx] != 0x1234; pcpu_idx++);
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
        values[pcpu_idx] = PCPU(cpu);
        void* entry = 0;
        char* kelf = load_kelf(kek, symbols, values, &entry);
        kelf_bases[cpu] = (uint64_t)kelf;
        kmemcpy((char*)IDT+16*13, (char*)entry, 2);
        kmemcpy((char*)IDT+16*13+6, (char*)entry+2, 6);
        kmemcpy((char*)IDT+16*13+4, "\3", 1);
        kmemcpy((char*)TSS(cpu)+28+3*8, (char*)entry+8, 8);
    }
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done loading\n", (uintptr_t)13);
    kmemzero((char*)IDT+16*1, 16);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"patching sysentvec... ", (uintptr_t)22);
    copyin(kdata_base + 0xd11bb8 + 14, &(const uint16_t[1]){0xdeb7}, 2);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
    p_kekcall = (char*)dlsym((void*)0x2001, "getpid") + 7;
    asm volatile("ud2");
    return 0;
}
