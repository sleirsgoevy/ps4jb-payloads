#include "../prosper0gdb/r0gdb.h"
#include "../gdb_stub/dbg.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

struct memfd
{
    char* buf;
    size_t size;
    size_t capacity;
};

void memfd_pwrite(struct memfd* fd, const void* buf, size_t sz, size_t offset)
{
    size_t cap2 = fd->capacity;
    while(offset + sz > cap2)
    {
        cap2 *= 2;
        if(!cap2)
            cap2 = 16384;
    }
    if(cap2 != fd->capacity)
    {
        char* p = mmap(fd->buf+fd->capacity, cap2-fd->capacity, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        if(p != fd->buf+fd->capacity)
        {
            munmap(p, cap2-fd->capacity);
            p = mmap(0, cap2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
            for(size_t i = 0; i < fd->capacity; i++)
                p[i] = fd->buf[i];
            munmap(fd->buf, fd->capacity);
            fd->buf = p;
        }
        fd->capacity = cap2;
    }
    const char* p_in = buf;
    for(size_t i = 0; i < sz; i++)
        fd->buf[i+offset] = p_in[i];
    if(offset + sz > fd->size)
        fd->size = offset + sz;
}

void memfd_close(struct memfd* fd)
{
    munmap(fd->buf, fd->capacity);
    fd->buf = 0;
    fd->size = 0;
    fd->capacity = 0;
}

static void print_string(const char* s)
{
    size_t l = 0;
    while(s[l])
        l++;
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)s, (uintptr_t)l);
}

static void print_hex(uint64_t i)
{
    char buf[17] = {0};
    char* p = buf;
    for(int j = 60; j >= 0; j -= 4)
    {
        int q = (i >> j) & 15;
        if(q < 10)
            *p++ = q + '0';
        else
            *p++ = q - 10 + 'a';
    }
    print_string(buf);
}

static void anykey(void)
{
    print_string("-- Press Enter to continue --");
    char c;
    gdb_remote_syscall("read", 1, 0, (uintptr_t)0, (uintptr_t)&c, (uintptr_t)1);
}

struct memfd dump_elf(const char* path)
{
    print_string("dumping ");
    print_string(path);
    print_string("...\n");
    struct memfd out = {0};
    static int dummy = 0;
    if(!dummy)
    {
        void* dummy_map = mmap20(0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        print_string("dummy_map = ");
        print_hex((uint64_t)dummy_map);
        print_string("\n");
        dummy = 1;
    }
    int fd = open(path, O_RDONLY);
    if(fd < 0)
    {
        print_string("open failed\n");
        return out;
    }
    off_t size = lseek(fd, 0, SEEK_END);
    if(size < 0)
    {
        print_string("lseek failed\n");
        close(fd);
        return out;
    }
    print_string("size = ");
    print_hex(size);
    print_string("\n");
    char* map = mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
    if(map == MAP_FAILED)
    {
        print_string("mmap failed");
        close(fd);
        return out;
    }
    print_string("map = ");
    print_hex((uint64_t)map);
    print_string("\n");
    for(size_t i = 0; i < size; i += 4096)
        *(volatile char*)(map+i);
    char* elf = map;
    while(elf[0] != 0x7f || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F')
        elf++;
    print_string("elf = ");
    print_hex((uint64_t)elf);
    print_string("\n");
    uint64_t phoff = *(uint64_t*)(elf+32);
    uint16_t phnum = *(uint16_t*)(elf+56);
    print_hex(phnum);
    print_string(" segments at ");
    print_hex(phoff);
    print_string("\n");
    memfd_pwrite(&out, elf, phoff+56*phnum, 0);
    for(int i = 0; i < phnum; i++)
    {
        char* p = elf + phoff + 56 * i;
        if(*(uint32_t*)p != 1) //PT_LOAD
            continue;
        uint64_t offset = *(uint64_t*)(p+8);
        uint64_t filesz = *(uint64_t*)(p+32);
        print_string("segment #");
        print_hex(i);
        print_string(", offset = ");
        print_hex(offset);
        print_string(", filesz = ");
        print_hex(filesz);
        print_string("\n");
        //anykey();
        void* map = mmap20(0, filesz, PROT_READ, MAP_SHARED|0x80000, fd, (uint64_t)i << 32);
        if(map == MAP_FAILED)
        {
            print_string("failed to mmap segment\n");
            memfd_close(&out);
            munmap(map, size);
            close(fd);
            return out;
        }
        print_string("map = ");
        print_hex((uint64_t)map);
        print_string("\n");
        memfd_pwrite(&out, map, filesz, offset);
        munmap(map, filesz);
    }
    munmap(map, size);
    close(fd);
    return out;
}

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
    dbg_enter();
    return 0;
}
