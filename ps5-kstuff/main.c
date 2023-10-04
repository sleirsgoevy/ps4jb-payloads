#include <sys/types.h>
#include <sys/mman.h>
#include "../prosper0gdb/r0gdb.h"
#include "../gdb_stub/dbg.h"

#include <signal.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>

static void infsleep(int sig)
{
    struct timespec ts = {1000, 0};
    for(;;)
        nanosleep(&ts, 0);
}

void kill_thread(void)
{
    struct sigaction sa = {
        .sa_handler = infsleep,
    };
    sigaction(SIGUSR1, &sa, 0);
    sigset_t ss = {0};
	ss.__bits[_SIG_WORD(SIGUSR1)] |= _SIG_BIT(SIGUSR1);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    for(int i = 0; i < 1000; i++)
        kill(getpid(), SIGUSR1);
}

void ignore_signals(void)
{
    struct sigaction sa = {
        .sa_handler = SIG_IGN,
    };
    for(int i = 1; i < 100; i++)
        if(i != SIGTRAP
        && i != SIGILL
        && i != SIGBUS
        && i != SIGINT
        && i != SIGSYS
        && i != SIGSEGV)
            sigaction20(i, &sa, 0);
}

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
#define GDT(i) (kdata_base+0x64cee30+0x68*(i))
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
            if(oia[0] + 8 > kernel_size)
                asm volatile("ud2");
            kpoke64(kptr+oia[0], oia[2]+value);
        }
        else if((uint32_t)oia[1] == 8)
        {
            if(oia[0] + 8 > kernel_size)
                asm volatile("ud2");
            kpoke64(kptr+oia[0], (uint64_t)(mapped_kptr+oia[2]));
        }
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

uint64_t kekcall(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t nr);

#define KEKCALL_GETPPID        0x000000027
#define KEKCALL_READ_DR        0x100000027
#define KEKCALL_WRITE_DR       0x200000027
#define KEKCALL_RDMSR          0x300000027
#define KEKCALL_REMOTE_SYSCALL 0x500000027
#define KEKCALL_CHECK          0xffffffff00000027

void* p_kekcall;
void* dlsym(void*, const char*);

void* malloc(size_t sz)
{
    return mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
}

uint64_t get_dmap_base(void)
{
    uint64_t ptrs[2];
    copyout(ptrs, kdata_base + 0x3257a98, sizeof(ptrs));
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

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
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
    shared_area = virt2phys(shared_area) + (1ull << 39);
    volatile int zero = 0; //hack to force runtime calculation of string pointers
    const char* symbols[] = {
        "add_rsp_iret"+zero,
        "copyin"+zero,
        "copyout"+zero,
        "crypt_message_resolve"+zero,
        "decryptMultipleSelfBlocks_epilogue"+zero,
        "decryptMultipleSelfBlocks_watchpoint_lr"+zero,
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
        "int1_handler"+zero,
        "int13_handler"+zero,
        ".ist_errc"+zero,
        ".ist_noerrc"+zero,
        ".ist4"+zero,
        "justreturn"+zero,
        "justreturn_pop"+zero,
        "kdata_base"+zero,
        "loadSelfSegment_epilogue"+zero,
        "loadSelfSegment_watchpoint"+zero,
        "loadSelfSegment_watchpoint_lr"+zero,
        "mdbg_call_fix"+zero,
        "mini_syscore_header"+zero,
        "mov_cr3_rax"+zero,
        "mov_rdi_cr3"+zero,
        "mprotect_fix_start"+zero,
        "mprotect_fix_end"+zero,
        "nop_ret"+zero,
        ".pcpu"+zero,
        "pop_all_except_rdi_iret"+zero,
        "pop_all_iret"+zero,
        "push_pop_all_iret"+zero,
        "rdmsr_end"+zero,
        "rdmsr_start"+zero,
        "rep_movsb_pop_rbp_ret"+zero,
        "sceSblServiceCryptAsync_deref_singleton"+zero,
        "sceSblServiceIsLoadable2"+zero,
        "sceSblServiceMailbox"+zero,
        "sceSblServiceMailbox_lr_decryptMultipleSelfBlocks"+zero,
        "sceSblServiceMailbox_lr_decryptSelfBlock"+zero,
        "sceSblServiceMailbox_lr_loadSelfSegment"+zero,
        "sceSblServiceMailbox_lr_verifyHeader"+zero,
        "shared_area"+zero,
        "soo_ioctl"+zero,
        "syscall_after"+zero,
        "syscall_before"+zero,
        "sysents"+zero,
        "sysents2"+zero,
        "swapgs_add_rsp_iret"+zero,
        ".tss"+zero,
        ".uelf_cr3"+zero,
        ".uelf_entry"+zero,
        "verifySuperBlock_call_mailbox"+zero,
        "wrmsr_ret"+zero,
        0,
    };
    uint64_t values[] = {
        kdata_base - 0x9cf853, // add_rsp_iret
        kdata_base - 0x9908e0, // copyin
        kdata_base - 0x990990, // copyout
        kdata_base - 0x479d60, // crypt_message_resolve
        kdata_base - 0x8a47d2, // decryptMultipleSelfBlocks_epilogue
        kdata_base - 0x8a4c55, // decryptMultipleSelfBlocks_watchpoint_lr
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
        int1_handler,          // int1_handler
        int13_handler,         // int13_handler
        0x1237,                // .ist_errc
        0x1238,                // .ist_noerrc
        0x1239,                // .ist4
        kdata_base - 0x9cf990, // justreturn
        kdata_base - 0x9cf988, // justreturn_pop
        kdata_base,            // kdata_base
        kdata_base - 0x8a54cd, // loadSelfSegment_epilogue
        kdata_base - 0x2cc918, // loadSelfSegment_watchpoint
        kdata_base - 0x8a5727, // loadSelfSegment_watchpoint_lr
        kdata_base - 0x631ea9, // mdbg_call_fix
        kdata_base + 0xdc16e8, // mini_syscore_header
        kdata_base - 0x396f9e, // mov_cr3_rax
        kdata_base - 0x39700e, // mov_rdi_cr3
        kdata_base - 0x90ac61, // mprotect_fix_start
        kdata_base - 0x90ac5b, // mprotect_fix_end
        kdata_base - 0x28a3a0, // nop_ret
        0x1234,                // .pcpu
        kdata_base - 0x9cf8a7, // pop_all_except_rdi_iret
        kdata_base - 0x9cf8ab, // pop_all_iret
        kdata_base - 0x96be70, // push_pop_all_iret
        kdata_base - 0x9d6cf9, // rdmsr_end
        kdata_base - 0x9d6d02, // rdmsr_start
        kdata_base - 0x990a55, // rep_movsb_pop_rbp_ret
        kdata_base - 0x8ed902, // sceSblServiceCryptAsync_deref_singleton
        kdata_base - 0x8a5c40, // sceSblServiceIsLoadable2
        kdata_base - 0x6824c0, // sceSblServiceMailbox
        kdata_base - 0x8a488c, // sceSblServiceMailbox_lr_decryptMultipleSelfBlocks
        kdata_base - 0x8a5014, // sceSblServiceMailbox_lr_decryptSelfBlock
        kdata_base - 0x8a5541, // sceSblServiceMailbox_lr_loadSelfSegment
        kdata_base - 0x8a58bc, // sceSblServiceMailbox_lr_verifyHeader
        shared_area, // shared_area
        kdata_base - 0x96eb98, // soo_ioctl
        kdata_base - 0x8022ee, // syscall_after
        kdata_base - 0x802311, // syscall_before
        kdata_base + 0x1709c0, // sysents
        kdata_base + 0x168410, // sysents2
        kdata_base - 0x9cf856, // swapgs_add_rsp_iret, XXX
        0x123a,                // .tss
        0x1235,                // .uelf_cr3
        0x1236,                // .uelf_entry
        kdata_base - 0x94a7f5, // verifySuperBlock_call_mailbox
        kdata_base - 0x9d20cc, // wrmsr_ret
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
        char* uelf = load_kelf(uek, symbols, values, uelf_base, &uelf_entry, 0x400000);
        uintptr_t uelf_cr3 = (uintptr_t)kmalloc(24576);
        uelf_cr3 = ((uelf_cr3 + 4095) | 4095) - 4095;
        uelf_cr3s[cpu] = uelf_cr3;
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
    uint64_t iret = kdata_base - 0x9cf84c;
    kmemcpy((char*)(IDT+16*2), (char*)&iret, 2);
    kmemcpy((char*)(IDT+16*2+6), (char*)&iret+2, 6);
    //kmemzero((char*)(IDT+16*1), 16);
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\napplying kdata patches... ", (uintptr_t)31);
    copyin(kdata_base + 0xd11bb8 + 14, &(const uint16_t[1]){0xdeb7}, 2); //native sysentvec
    copyin(kdata_base + 0xd11d30 + 14, &(const uint16_t[1]){0xdeb7}, 2); //ps4 sysentvec
    copyin(kdata_base + 0x2e31830 + 11*8 + 2*8 + 6, &(const uint16_t[1]){0xdeb7}, 2); //crypt xts
    copyin(kdata_base + 0x2e31830 + 11*8 + 9*8 + 6, &(const uint16_t[1]){0xdeb7}, 2); //crypt hmac
    /*for(int i = 0; i < 22; i++)
        copyin(kdata_base + 0x2e31830 + i*8 + 6, &(const uint16_t[1]){0xdeb7}, 2);*/
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)"done\n", (uintptr_t)5);
    p_kekcall = (char*)dlsym((void*)0x2001, "getpid") + 7;
    //restore the gdb_stub's SIGTRAP handler
    struct sigaction sa;
    sigaction(SIGBUS, 0, &sa);
    sigaction(SIGTRAP, &sa, 0);
    sigaction(SIGPIPE, &sa, 0);
    copyin(IDT+16*9+5, "\x8e", 1);
    copyin(IDT+16*179+5, "\x8e", 1);
    asm volatile("ud2");
    return 0;
}

/*
TEMPORARY CODE

This should either go to some separate place ("utils.c" in r0gdb perhaps), or be removed completely.
*/

#define sysctl __sysctl
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/thr.h>
#include <sys/sysctl.h>
#include <machine/sysarch.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#define SYS_mdbg_call 573
#define SYS_dynlib_dlsym 591
#define SYS_dynlib_get_info_ex 608

void inject_payload(int pid)
{
    if(kekcall(0, 0, 0, 0, 0, 0, KEKCALL_CHECK))
        return;
    static int sock = -1;
    if(sock < 0)
    {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sin = {
            .sin_family = AF_INET,
            .sin_addr = {.s_addr = 0},
            .sin_port = __builtin_bswap16(9020),
        };
        bind(sock, (void*)&sin, sizeof(sin));
        listen(sock, 1);
    }
    int sock2 = accept(sock, 0, 0);
    char* buf = mmap(0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    size_t sz = 0;
    size_t cap = 16384;
    for(;;)
    {
        if(sz == cap)
        {
            cap *= 2;
            char* buf2 = mmap(0, cap, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
            for(size_t i = 0; i < sz; i++)
                buf2[i] = buf[i];
            munmap(buf, sz);
            buf = buf2;
        }
        ssize_t chk = read(sock2, buf+sz, cap-sz);
        if(chk <= 0)
            break;
        sz += chk;
    }
    static const char shellcode[] = {
        0x55, //push rbp
        0x48, 0x8b, 0xfc, //mov rdi, rsp
        0x31, 0xf6, //xor esi, esi
        0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, //movabs rdx, ...
        0x48, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, //movabs rcx, ...
        0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, //movabs rax, ...
        0xff, 0xd0, //call rax
        0x31, 0xff, //xor edi, edi
        0xb8, SYS_thr_exit&255, SYS_thr_exit>>8, 0, 0,
        0xff, 0x25, 0, 0, 0, 0, //jmp qword [rip]
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    if(cap - sz < sizeof(shellcode))
    {
        cap *= 2;
        char* buf2 = mmap(0, cap, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        for(size_t i = 0; i < sz; i++)
            buf2[i] = buf[i];
        munmap(buf, sz);
        buf = buf2;
    }
    size_t shellcode_offset = sz;
    for(size_t i = 0; i < sizeof(shellcode); i++)
        buf[sz++] = shellcode[i];
    uint64_t target_pointer = kekcall(pid, SYS_mmap, (uint64_t)(const uint64_t[6]){0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0}, 0, 0, 0, KEKCALL_REMOTE_SYSCALL);
    if(target_pointer + 1 <= 4096)
        asm volatile("ud2");
    uint64_t target_stack = kekcall(pid, SYS_mmap, (uint64_t)(const uint64_t[6]){0, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0}, 0, 0, 0, KEKCALL_REMOTE_SYSCALL);
    if(target_stack + 1 <= 4096)
        asm volatile("ud2");
    if(kekcall(pid, SYS_mprotect, (uint64_t)(const uint64_t[6]){target_pointer, sz, PROT_READ|PROT_WRITE|PROT_EXEC}, 0, 0, 0, KEKCALL_REMOTE_SYSCALL))
        asm volatile("ud2");
    *(uint64_t*)(buf+shellcode_offset+8) = target_pointer;
    kekcall(pid, SYS_dynlib_dlsym, (uint64_t)(const uint64_t[6]){0x2001, (uint64_t)"sceKernelDlsym", (uint64_t)(buf+shellcode_offset+18)}, 0, 0, 0, KEKCALL_REMOTE_SYSCALL);
    if(!*(uint64_t*)(buf+shellcode_offset+18))
        asm volatile("ud2");
    kekcall(pid, SYS_dynlib_dlsym, (uint64_t)(const uint64_t[6]){0x2001, (uint64_t)"pthread_create", (uint64_t)(buf+shellcode_offset+28)}, 0, 0, 0, KEKCALL_REMOTE_SYSCALL);
    if(!*(uint64_t*)(buf+shellcode_offset+28))
        asm volatile("ud2");
    kekcall(pid, SYS_dynlib_dlsym, (uint64_t)(const uint64_t[6]){0x2001, (uint64_t)"getpid", (uint64_t)(buf+shellcode_offset+51)}, 0, 0, 0, KEKCALL_REMOTE_SYSCALL);
    if(!*(uint64_t*)(buf+shellcode_offset+51))
        asm volatile("ud2");
    *(uint64_t*)(buf+shellcode_offset+51) += 7;
    {
        uint64_t arg1[4] = {1, 0x13};
        uint64_t arg2[8] = {pid, target_pointer, (uint64_t)buf, sz};
        uint64_t arg3[4] = {0};
        if(kekcall((uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, 0, 0, 0, SYS_mdbg_call))
            asm volatile("ud2");
    }
    {
        uint64_t arg1[4] = {1, 0x13};
        uint64_t arg2[8] = {pid, target_stack+16, (uint64_t)&target_stack, 8};
        uint64_t arg3[4] = {0};
        if(kekcall((uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, 0, 0, 0, SYS_mdbg_call))
            asm volatile("ud2");
    }
    {
        uint64_t arg1[4] = {1, 0x13};
        uint64_t arg2[8] = {pid, target_stack+0x1a8, (uint64_t)&target_stack, 8};
        uint64_t arg3[4] = {0};
        if(kekcall((uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, 0, 0, 0, SYS_mdbg_call))
            asm volatile("ud2");
    }
    munmap(buf, sz);
    {
        struct thr_param param = {0};
        long x, y;
        param.start_func = (void*)(target_pointer+shellcode_offset);
        param.stack_base = (void*)target_stack;
        param.stack_size = 65536;
        param.tls_size = 1;
        param.arg = 0;
        if(kekcall(pid, SYS_sysarch, (uint64_t)(const uint64_t[6]){AMD64_GET_FSBASE, (uint64_t)&param.tls_base}, 0, 0, 0, KEKCALL_REMOTE_SYSCALL))
            asm volatile("ud2");
        if(kekcall(pid, SYS_thr_new, (uint64_t)(const uint64_t[6]){(uint64_t)&param, sizeof(param)}, 0, 0, 0, KEKCALL_REMOTE_SYSCALL))
            asm volatile("ud2");
    }
}

void* klog_server(void* arg)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = 0 },
        .sin_port = 0x0e27, //9998
    };
    bind(sock, (void*)&sin, sizeof(sin));
    listen(sock, 1);
new_conn:
    int sock2 = accept(sock, NULL, NULL);
    char buf[512];
    int fd1 = open("/dev/klog", O_RDONLY);
    for(;;)
    {
        ssize_t chk = read(fd1, buf, sizeof(buf));
        if(chk < 0)
            break;
        char* p = buf;
        while(chk > 0)
        {
            ssize_t chk1 = write(sock2, p, chk);
            if(chk1 <= 0)
            {
                close(sock2);
                goto new_conn;
            }
            chk -= chk1;
            p += chk1;
        }
    }
}

int find_proc(const char* name)
{
    char buf[1097] = {0};
    for(int pid = 1; pid < 1024; pid++)
    {
        size_t sz = 1096;
        int key[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        sysctl(key, 4, buf, &sz, 0, 0);
        const char* a = buf + 447;
        const char* b = name;
        while(*a && *a++ == *b++);
        if(!*a && !*b)
            return pid;
    }
    return -1;
}

static int64_t do_remote_syscall(int pid, int sysc, ...)
{
    static uint64_t args_p = 0;
    if(!args_p)
        args_p = r0gdb_kmalloc(48);
    uint64_t args[6];
    va_list l;
    va_start(l, sysc);
    for(int i = 0; i < 6; i++)
        args[i] = va_arg(l, uint64_t);
    va_end(l);
    uint64_t proc;
    uint64_t target = 0;
    copyout(&proc, kdata_base+0x27edcb8, 8);
    while(proc)
    {
        uint32_t pid1;
        copyout(&pid1, proc+0xbc, 4);
        if(pid1 == pid)
        {
            target = proc;
            break;
        }
        copyout(&proc, proc, 8);
    }
    if(!target)
        asm volatile("ud2");
    uint64_t target_thread;
    copyout(&target_thread, target+16, 8);
    copyin(args_p, args, 48);
    uint64_t syscall_fn;
    copyout(&syscall_fn, kdata_base+0x1709c0+48*sysc+8, 8);
    int err = r0gdb_kfncall(syscall_fn, target_thread, args_p);
    if(err)
        return -err;
    int64_t ans;
    copyout(&ans, target_thread+0x408, 8);
    return ans;
}

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

static uint64_t shellcore_args_base;

static void temp_patch_shellcore(int do_lk)
{
    int pid = find_proc("SceShellCore");
    struct module_info_ex mod_info;
    mod_info.st_size = sizeof(mod_info);
    do_remote_syscall(pid, SYS_dynlib_get_info_ex, 0, 0, &mod_info);
    uint64_t shellcore_base = mod_info.eh_frame_hdr_addr - 0x13c0000;
    mod_info.st_size = sizeof(mod_info);
    do_remote_syscall(pid, SYS_dynlib_get_info_ex, 0x2001, 0, &mod_info);
    uint64_t libkernel_base = mod_info.eh_frame_hdr_addr - 0x44000;
    shellcore_args_base = do_remote_syscall(pid, SYS_mmap, 0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    struct
    {
        uint64_t addr;
        void* data;
        size_t sz;
    } patches[] = {
        {shellcore_base+0x974fe0, "\x31\xc0\xc3", 3},
        {shellcore_base+0x974bb0, "\x31\xc0\xc3", 3},
        {shellcore_base+0x5307f9, "\xeb\x04", 2},
        {shellcore_base+0x26f35c, "\xeb\x04", 2},
        {shellcore_base+0x54e1f0, "\xeb", 1},
        {shellcore_base+0x536e1d, "\x90\xe9", 2},
        {libkernel_base+0x18f0, "\x48\xb8\xef\xbe\xad\xde\xef\xbe\xad\xde\x48\x89\x38\x48\x89\x70\x08\x48\x89\x50\x10\xeb\xfe", do_lk ? 23 : 0},
        {libkernel_base+0x18f2, &shellcore_args_base, do_lk ? 8 : 0},
    };
    for(int i = 0; i < sizeof(patches) / sizeof(*patches); i++)
    {
        uint64_t arg1[4] = {1, 0x13};
        uint64_t arg2[8] = {pid, patches[i].addr, (uint64_t)patches[i].data, patches[i].sz};
        uint64_t arg3[4] = {0};
        mdbg_call_20(arg1, arg2, arg3);
    }
}

static void* get_nmount_args(void)
{
    int pid = find_proc("SceShellCore");
    uint64_t args[3];
#define READ(dst, src, sz) (mdbg_call_20((uint64_t[4]){1, 0x12}, (uint64_t[8]){pid, (src), (uint64_t)(dst), (sz)}, (uint64_t[4]){}))
    READ(args, shellcore_args_base, 24);
    uint64_t* ptrs = malloc(sizeof(*ptrs) * args[1] * 2);
    READ(ptrs, args[0], sizeof(*ptrs) * args[1] * 2);
    for(int i = 0; i < args[1]; i++)
    {
        uint64_t ptr = ptrs[2*i];
        uint64_t sz = ptrs[2*i+1];
        char* buf = malloc(sz+1);
        READ(buf, ptr, sz);
        buf[sz] = 0;
        ptrs[2*i] = (uint64_t)buf;
    }
#undef READ
    return ptrs;
}

int my_nmount(void* a, int b, int c)
{
    return kekcall((uintptr_t)a, b, c, 0, 0, 0, SYS_nmount);
}
