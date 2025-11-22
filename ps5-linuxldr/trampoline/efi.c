#pragma GCC optimize("Oz")

#include <stdint.h>
#include <stddef.h>

#define EFI __attribute__((ms_abi,section(".efi")))

static EFI int enosys(void)
{
    return -3; //EFI_UNSUPPORTED
}

__attribute__((section(".persist"))) uint64_t efi_memmap[1][5] = {
    {5, 0, 0, 0, 1ull << 63},
};

__attribute__((section(".efi"))) static void putchar(char c)
{
    volatile uint32_t* uart = (volatile uint32_t*)(efi_memmap[0][2] + 0xc1010100);
    while((uart[3] & 0x800));
    uart[1] = (uint8_t)c;
}

__attribute__((section(".efi"))) static void putstr(const char* s)
{
    while(*s)
        putchar(*s++);
}

#define STR(x) ({\
    __attribute__((section(".efistr"))) static const char s[] = (x);\
    s;\
})

__attribute__((section(".persist"))) struct
{
    char guid[16];
    size_t ptr_table;
} efi_conf_tables[1] = {};

__attribute__((section(".persist"))) uint64_t efi_system_table[15];
__attribute__((section(".persist"))) uint64_t efi_runtime_table[17];
__attribute__((section(".persist"))) uint16_t efi_vendor[100] = {'s', 'l', 'e', 'i', 'r', 's', 'g', 'o', 'e', 'v', 'y'};

static EFI int set_virtual_address_map(size_t sz, size_t descr_sz, uint32_t descr_version, uintptr_t memmap)
{
    if(sz != sizeof(efi_memmap) || descr_sz != sizeof(efi_memmap[0]))
        return -3;
    uintptr_t shift = *(uint64_t*)(memmap + 16);
    efi_memmap[0][2] = shift;
    efi_system_table[11] += shift;
    for(size_t i = 1; i < 17; i++)
        efi_runtime_table[i] += shift;
    return 0;
}

__attribute__((section(".efi"))) static void send_icc(int major, int minor, const uint8_t* buf, size_t sz)
{
    uint8_t message[32] = {0};
    message[0] = 0x42;
    message[1] = major;
    message[2] = minor;
    message[3] = minor >> 8;
    message[4] = 2;
    message[6] = 1;
    message[8] = 0x20;
    for(size_t i = 0; i < sz; i++)
        message[i+12] = buf[i];
    uint16_t cksum = 0;
    for(size_t i = 0; i < 32; i++)
        cksum += message[i];
    message[10] = cksum;
    message[11] = cksum >> 8;
    *(volatile uint16_t*)(efi_memmap[0][2] + 0x854007f4) = 0;
    volatile uint8_t* dst = (volatile uint8_t*)(efi_memmap[0][2] + 0x85400000);
    for(size_t i = 0; i < 32; i++)
        dst[i] = message[i];
    *(volatile uint16_t*)(efi_memmap[0][2] + 0x854007f0) = 1;
    *(volatile uint32_t*)(efi_memmap[0][2] + 0x85308004) = 1;
    for(;;)
        asm volatile("");
}

static EFI int reset_system(uint32_t type, uint32_t status, size_t data_size, void* data)
{
    if(type >= 3)
        return -3;
    char cmd[6] = {};
    cmd[2] = 2;
    cmd[4] = 1;
    cmd[1] = type != 2;
    send_icc(4, 1, cmd, 6);
    return 0;
}

__attribute__((section(".persist"))) uint64_t ref_tsc = 0;
__attribute__((section(".persist"))) int64_t ref_seconds = 0;

struct efi_time
{
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t pad1;
    uint32_t nanosecond;
    int16_t timezone;
    uint8_t daylight;
    uint8_t pad2;
};

struct efi_time_capabilities
{
    uint32_t resolution;
    uint32_t accuracy;
    uint8_t sets_to_zero;
};

enum { TSC_FREQ = 1596300166 };

static EFI int get_time(struct efi_time* t, struct efi_time_capabilities* cap)
{
    uint32_t eax, edx;
    asm volatile("rdtsc":"=a"(eax),"=d"(edx));
    uint64_t tsc = (uint64_t)edx << 32 | eax;
    uint64_t time_passed = tsc - ref_tsc;
    int64_t seconds = ref_seconds + tsc / TSC_FREQ;
    uint64_t nanoseconds = (tsc % TSC_FREQ) * 1000000000 / TSC_FREQ;
    int secs = (86400 + seconds % 86400) % 86400;
    int64_t days_since_1_mar_2000 = (seconds - secs) / 86400 - 30 * 365 - 7 - 31 - 29;
    int64_t days_since_y400 = (365 * 400 + 97 + days_since_1_mar_2000 % (365 * 400 + 97)) % (365 * 400 + 97);
    int64_t year = 2000 + 400 * ((days_since_1_mar_2000 - days_since_y400) / (365 * 400 + 97));
    if(days_since_y400 == 365 * 400 + 96)
    {
        year += 399;
        days_since_y400 = 365;
    }
    else
    {
        year += 100 * (days_since_y400 / (365 * 100 + 24));
        days_since_y400 %= 365 * 100 + 24;
        year += 4 * (days_since_y400 / (365 * 4 + 1));
        days_since_y400 %= 365 * 4 + 1;
        if(days_since_y400 == 365 * 4)
        {
            year += 3;
            days_since_y400 = 365;
        }
        else
        {
            year += days_since_y400 / 365;
            days_since_y400 %= 365;
        }
    }
    int month = 3;
    int day = days_since_y400;
    month += 5 * (day / (31 + 30 + 31 + 30 + 31));
    day %= (31 + 30 + 31 + 30 + 31);
    month += 2 * (day / (31 + 30));
    day %= (31 + 30);
    if(day >= 31)
    {
        month++;
        day -= 31;
    }
    if(month > 12)
    {
        month -= 12;
        year++;
    }
    day++;
    if(t)
    {
        t->year = year;
        t->month = month;
        t->day = day;
        t->hour = secs / 3600;
        t->minute = (secs % 3600) / 60;
        t->second = secs % 60;
        t->nanosecond = nanoseconds;
        t->timezone = 0;
        t->daylight = 0;
    }
    if(cap)
    {
        cap->resolution = 0;
        cap->accuracy = -1;
        cap->sets_to_zero = 0;
    }
    return 0;
}

struct e820_map_entry
{
    uint64_t start;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

void init_efi_runtime(uintptr_t zero_page)
{
    for(size_t i = 0; i < 15; i++)
        efi_system_table[i] = 0xb3b3b3b3b3b3b3b3;
    efi_system_table[0] = 0x5453595320494249;
    efi_system_table[3] = (uintptr_t)efi_vendor;
    efi_system_table[11] = (uintptr_t)efi_runtime_table;
    efi_system_table[13] = 1;
    efi_system_table[14] = (uintptr_t)efi_conf_tables;
    for(size_t i = 0; i < 17; i++)
        efi_runtime_table[i] = (uintptr_t)enosys;
    efi_runtime_table[3] = (uintptr_t)get_time;
    efi_runtime_table[7] = (uintptr_t)set_virtual_address_map;
    efi_runtime_table[13] = (uintptr_t)reset_system;
    *(uint32_t*)(zero_page + 0x1c0) = 0x34364c45; // 'EL64'
    *(uint32_t*)(zero_page + 0x1c4) = (uint32_t)(uintptr_t)efi_system_table;
    *(uint32_t*)(zero_page + 0x1c8) = 40;
    *(uint32_t*)(zero_page + 0x1d0) = (uint32_t)(uintptr_t)efi_memmap;
    *(uint32_t*)(zero_page + 0x1d4) = sizeof(efi_memmap);
    *(uint32_t*)(zero_page + 0x1d8) = (uint32_t)((uintptr_t)efi_system_table >> 32);
    *(uint32_t*)(zero_page + 0x1dc) = (uint32_t)((uintptr_t)efi_memmap >> 32);
    size_t n_e820 = *(uint8_t*)(zero_page + 0x1e8);
    struct e820_map_entry* e820_map = (void*)(zero_page + 0x2d0);
    for(size_t i = 0; i < n_e820; i++)
    {
        size_t addr_end = (e820_map[i].start + e820_map[i].size + 4095) >> 12;
        if(addr_end > efi_memmap[0][3])
            efi_memmap[0][3] = addr_end;
    }
}
