#include <stdint.h>
#include <stddef.h>

__attribute__((section(".persist"),aligned(4096))) uint64_t pml4[512];
__attribute__((section(".persist"),aligned(4096))) uint64_t pml3[512];
__attribute__((section(".persist"),aligned(4096))) uint64_t iopml4[512];

static void putchar(char c)
{
    while((*(volatile uint32_t*)0xc101010c & 0x800));
    *(volatile uint32_t*)0xc1010104 = (uint8_t)c;
}

static void putstr(const char* s)
{
    while(*s)
        putchar(*s++);
}

static void puthex(uint64_t n)
{
    for(size_t i = 60; i > 0; i -= 4)
    {
        uint64_t v = n >> i;
        if(v)
            putchar("0123456789abcdef"[v & 15]);
    }
    putchar("0123456789abcdef"[n & 15]);
}

static uint32_t our_cpu(void)
{
    uint32_t eax, edx;
    asm volatile("cpuid":"=d"(edx),"=a"(eax):"a"(11):"ecx","ebx");
    return edx;
}

static uint64_t rdmsr(uint32_t arg)
{
    uint32_t eax, edx;
    asm volatile("rdmsr":"=a"(eax),"=d"(edx):"c"(arg));
    return (uint64_t)edx << 32 | eax;
}

static uint64_t rdtsc(void)
{
    uint32_t eax, edx;
    asm volatile("rdtsc":"=a"(eax),"=d"(edx));
    return (uint64_t)edx << 32 | eax;
}

void hijack_cpus(volatile uint32_t* apic)
{
    putstr("\r\n# ps5-linuxldr is booting Linux\r\n\r\nHijacking other CPUs... ");
    int our = our_cpu();
    for(int i = 0; i < 16; i++)
        if(i != our)
        {
            while((apic[0x300/4] & 0x1000));
            apic[0x310/4] = (uint32_t)i << 24;
            apic[0x300/4] = 0x40f0;
        }
    putstr("done\r\n");
}

static uint64_t iommu_mmio;

__attribute__((section(".persist"),aligned(4096))) static volatile char iommu_guest_buffers[20480];

static uint64_t iommu_set_guest_buffers(uint64_t cmdbuf1, uint64_t cmdbuf2, uint64_t evlog)
{
    uint64_t rax;
    asm volatile("vmmcall":"=a"(rax):"a"(6),"b"(cmdbuf1),"c"(cmdbuf2),"d"(evlog));
    return rax;
}

static uint64_t iommu_enable_device(uint16_t which)
{
    uint64_t rax;
    asm volatile("vmmcall":"=a"(rax):"a"(7),"b"((uint64_t)which));
    return rax;
}

static uint64_t iommu_bind_pasid(uint16_t which, int pasid, uint64_t gcr3)
{
    uint64_t rax;
    asm volatile("vmmcall":"=a"(rax):"a"(8),"b"((uint64_t)which),"c"((uint64_t)pasid),"d"(gcr3));
    return rax;
}

static uint64_t iommu_unbind_pasid(uint16_t which, int pasid)
{
    uint64_t rax;
    asm volatile("vmmcall":"=a"(rax):"a"(9),"b"((uint64_t)which),"c"((uint64_t)pasid));
}

static void iommu_wait_command_completion(void)
{
    uint64_t rax;
    do
        asm volatile("vmmcall":"=a"(rax):"a"(10));
    while(rax);
}

__attribute__((section(".firmware_wakeup_table"),aligned(4096))) struct
{
    uint32_t command;
    uint32_t apic_id;
    uint64_t wakeup_vector;
    char os_reserved[2032];
    char firmware_reserved[2048];
} firmware_wakeup_table;

static inline void checksum(uint8_t* table_start, uint8_t* table_end)
{
    table_start[9] = 0;
    uint8_t cksum = 0;
    for(uint8_t* i = table_start; i < table_end; i++)
        cksum += *i;
    table_start[9] = -cksum;
}

extern char reset_vector[];

enum {
    MADT = 'C' << 24 | 'I' << 16 | 'P' << 8 | 'A',
    FADT = 'P' << 24 | 'C' << 16 | 'A' << 8 | 'F',
    IVRS = 'S' << 24 | 'R' << 16 | 'V' << 8 | 'I',
    VFCT = 'T' << 24 | 'C' << 16 | 'F' << 8 | 'V',
};

static uintptr_t find_table(uintptr_t xsdt, uint32_t which)
{
    uint64_t* end = (uint64_t*)(xsdt + *(uint32_t*)(xsdt + 4));
    for(uint64_t* i = (uint64_t*)(xsdt + 36); i < end; i++)
        if(*(uint32_t*)*i == which)
            return *i;
}

#define REPLACE_TABLE(fn, ty)\
static void fn(uintptr_t sdt, uint32_t which, uintptr_t new_madt)\
{\
    ty* end = (ty*)(sdt + *(uint32_t*)(sdt + 4));\
    for(ty* i = (ty*)(sdt + 36); i < end; i++)\
        if(*(uint32_t*)(uintptr_t)*i == which)\
            *i = new_madt;\
    checksum((uint8_t*)sdt, (uint8_t*)end);\
}

REPLACE_TABLE(replace_in_rsdt, uint32_t)
REPLACE_TABLE(replace_in_xsdt, uint64_t)
#undef REPLACE_TABLE

#if 0
__attribute__((section(".persist"))) static struct vfct
{
    uint32_t signature;
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oemid[6];
    char oemtableid[8];
    uint32_t oemrevision;
    uint32_t creatorid;
    uint32_t creatorrevision;
    char uuid[16];
    uint32_t vbios_offset;
    uint32_t reserved;
    uint32_t lib1_offset;
    struct
    {
        uint32_t bus;
        uint32_t dev;
        uint32_t fn;
        uint16_t vid;
        uint16_t pid;
        uint16_t ssvid;
        uint16_t ssid;
        uint32_t revision;
        uint32_t image_length;
    } __attribute__((packed)) image_header;
    char content[0x40000];
} __attribute__((packed)) vfct = {
    .signature = VFCT,
    .length = sizeof(vfct),
    .vbios_offset = __builtin_offsetof(struct vfct, image_header),
    .image_header = {
        .bus = 0x20,
        .dev = 0,
        .fn = 0,
        .vid = 0x1002,
        .pid = 0x13fb,
        .image_length = 0x40000,
    },
};

asm("vbios:\n.incbin \"../videobios.bin\"");
extern char vbios[];
#endif

static void init_acpi(uintptr_t zero_page)
{
    uintptr_t rsdp = *(uint64_t*)(zero_page + 0x70);
    uintptr_t madt = find_table(*(uint64_t*)(rsdp + 24), MADT);
    uint32_t madt_size = *(uint32_t*)(madt + 4);
    if(madt_size + 24 > 2048)
    {
        putstr("MADT too large\n");
        return;
    }
    uint8_t* new_madt = firmware_wakeup_table.firmware_reserved;
    for(size_t i = 0; i < madt_size; i++)
        new_madt[i] = ((uint8_t*)madt)[i];
    *(uint32_t*)(new_madt + 4) += 24;
    struct
    {
        uint8_t type;
        uint8_t length;
        uint16_t version;
        uint32_t reserved;
        uint64_t mailbox_address;
        uint64_t reset_vector;
    } wakeup = {
        .type = 16,
        .length = 24,
        .mailbox_address = (uintptr_t)&firmware_wakeup_table,
        .reset_vector = (uintptr_t)reset_vector,
    };
    for(size_t i = 0; i < 24; i++)
        new_madt[madt_size+i] = ((uint8_t*)&wakeup)[i];
    checksum(new_madt, new_madt + madt_size + 24);
    replace_in_rsdt(*(uint32_t*)(rsdp + 16), MADT, (uintptr_t)new_madt);
    replace_in_xsdt(*(uint64_t*)(rsdp + 24), MADT, (uintptr_t)new_madt);
    uintptr_t fadt = find_table(*(uint64_t*)(rsdp + 24), FADT);
    uint32_t fadt_size = *(uint32_t*)(fadt + 4);
    *(uint32_t*)(fadt + 0x70) = 1 << 20;
    //*(uint64_t*)(fadt + 0xf8) = *(uint64_t*)(fadt + 0x104) = 0;
    checksum((char*)fadt, (char*)(fadt + fadt_size));
#if 0
    for(size_t i = 0; i < 0x40000; i++)
        vfct.content[i] = vbios[i];
    checksum((char*)&vfct, (char*)(1+&vfct));
    replace_in_rsdt(*(uint32_t*)(rsdp + 16), IVRS, (uintptr_t)&vfct);
    replace_in_xsdt(*(uint64_t*)(rsdp + 24), IVRS, (uintptr_t)&vfct);
#endif
}

void init_efi_runtime(uintptr_t zero_page);

void boot_cpu_init(uintptr_t zero_page)
{
    pml4[0] = (uintptr_t)pml3 | 3;
    iopml4[0] = (uintptr_t)pml3 | 7 | (15ull << 52);
    for(size_t i = 0; i < 512; i++)
        pml3[i] = (i << 30) | 135 | (15ull << 52);
    iommu_set_guest_buffers((uint64_t)iommu_guest_buffers, (uint64_t)iommu_guest_buffers + 8192, (uint64_t)iommu_guest_buffers + 16384);
    uint64_t devices[] = {/*0x2000,*/ 0x2001, 0x2004, 0x2005, 0x4003, 0x4004, 0x4006};
    for(size_t i = 0; i < sizeof(devices) / sizeof(*devices); i++)
        iommu_bind_pasid(devices[i], 0, (uint64_t)iopml4);
    for(int i = 0; i < 0x800; i++)
    {
        if(i % 100 == 0)
            iommu_wait_command_completion();
        iommu_bind_pasid(0x2000, i, (uint64_t)iopml4);
    }
    iommu_wait_command_completion();
    init_acpi(zero_page);
    init_efi_runtime(zero_page);
}
