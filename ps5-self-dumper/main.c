#include "../prosper0gdb/r0gdb.h"
#ifdef DEBUG
#include "../gdb_stub/dbg.h"
#endif
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

struct memfd
{
    char* buf;
    size_t size;
    size_t capacity;
};

static int writeall(int fd, const void* buf, size_t sz)
{
    const char* p = buf;
    while(sz)
    {
        ssize_t chk = write(fd, p, sz);
        if(chk <= 0)
            return -1;
        sz -= chk;
        p += chk;
    }
    return 0;
}

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
#ifdef DEBUG
    size_t l = 0;
    while(s[l])
        l++;
    gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)s, (uintptr_t)l);
#endif
}

static void print_hex(uint64_t i)
{
#ifdef DEBUG
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
#endif
}

struct memfd do_dump_elf(const char* path)
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

struct memfd dump_elf(const char* path)
{
    if(path[0] != '/' || path[1] != 's' || path[2] != 'y' || path[3] != 's' || path[4] != 't' || path[5] != 'e' || path[6] != 'm' ||
    (path[7] != '/' && (path[7] != '_' || path[8] != 'e' || path[9] != 'x' || path[10] != '/')))
    {
        print_string("copying ");
        print_string(path);
        print_string(" to /data/dump_target.elf\n");
        int fd1 = open(path, O_RDONLY);
        int fd2 = open("/data/dump_target.elf", O_WRONLY|O_CREAT|O_TRUNC, 0777);
        char buf[4096];
        ssize_t chk;
        while((chk = read(fd1, buf, 4096)) > 0)
        {
            size_t off = 0;
            while(off < chk)
            {
                ssize_t chk2 = write(fd2, buf+off, chk-off);
                if(chk2 <= 0)
                {
                    close(fd1);
                    close(fd2);
                    goto copy_failed;
                }
                off += chk2;
            }
        }
        close(fd1);
        close(fd2);
        if(chk < 0)
        {
        copy_failed:
            print_string("copying ");
            print_string(path);
            print_string(" failed\n");
            return (struct memfd){};
        }
        struct memfd ans = do_dump_elf("/data/dump_target.elf");
        unlink("/data/dump_target.elf");
        return ans;
    }
    return do_dump_elf(path);
}

struct my_dirent
{
    uintptr_t path;
    int is_file;
};

struct memfd listdirs(struct my_dirent* dirs, int* have_dirs)
{
    char* names = (void*)dirs;
    struct memfd buf1 = {0};
    struct memfd buf2 = {0};
    size_t pos1 = 0;
    size_t pos2 = 0;
    for(size_t i = 0; dirs[i].path; i++)
    {
        size_t l = 0;
        while(names[dirs[i].path+l])
            l++;
        if(dirs[i].is_file)
        {
            size_t p = pos1;
            memfd_pwrite(&buf1, names+dirs[i].path, l+1, pos1);
            pos1 += l + 1;
            struct my_dirent new = {
                .path = p+1,
                .is_file = 1,
            };
            memfd_pwrite(&buf2, &new, sizeof(new), pos2);
            pos2 += sizeof(new);
        }
        else
        {
            int fd = open(names+dirs[i].path, O_RDONLY);
            if(fd < 0)
                continue;
            char* de_buf = mmap(0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
            int size;
            while((size = getdents(fd, de_buf, 16384)) > 0)
                for(int j = 0; j < size;)
                {
                    struct dirent* de = (void*)(de_buf+j);
                    j += de->d_reclen;
                    if(de->d_namlen <= 2
                    && (!de->d_namlen || de->d_name[0] == '.')
                    && (de->d_namlen == 1 || de->d_name[1] == '.'))
                        continue;
                    size_t p = pos1;
                    memfd_pwrite(&buf1, names+dirs[i].path, l, pos1);
                    pos1 += l;
                    memfd_pwrite(&buf1, "/", 1, pos1);
                    pos1++;
                    memfd_pwrite(&buf1, de->d_name, de->d_namlen, pos1);
                    pos1 += de->d_namlen;
                    memfd_pwrite(&buf1, "", 1, pos1);
                    pos1++;
                    struct my_dirent new = {
                        .path = p+1,
                        .is_file = de->d_type != DT_DIR,
                    };
                    memfd_pwrite(&buf2, &new, sizeof(new), pos2);
                    pos2 += sizeof(new);
                    if(have_dirs && !new.is_file)
                        *have_dirs = 1;
                }
            munmap(de_buf, 16384);
            close(fd);
        }
    }
    struct my_dirent sentinel = {0};
    memfd_pwrite(&buf2, &sentinel, sizeof(sentinel), pos2);
    pos2 += sizeof(sentinel);
    memfd_pwrite(&buf2, buf1.buf, buf1.size, pos2);
    memfd_close(&buf1);
    struct my_dirent* dirs2 = (void*)buf2.buf;
    for(size_t i = 0; dirs2[i].path; i++)
        dirs2[i].path += pos2 - 1;
    return buf2;
}

struct memfd tree(const char** paths)
{
    size_t npaths = 0;
    while(paths[npaths])
        npaths++;
    size_t pos1 = (npaths + 1) * sizeof(struct my_dirent);
    size_t pos2 = 0;
    struct memfd obj = {0};
    for(size_t i = 0; paths[i]; i++)
    {
        const char* cur = paths[i];
        int is_file = 0;
        if(cur[0] == '!')
        {
            cur++;
            is_file = 1;
        }
        size_t p = pos1;
        size_t l = 0;
        while(cur[l])
            l++;
        memfd_pwrite(&obj, cur, l+1, pos1);
        pos1 += l + 1;
        struct my_dirent entry = {
            .path = p,
            .is_file = is_file,
        };
        memfd_pwrite(&obj, &entry, sizeof(entry), pos2);
        pos2 += sizeof(entry);
    }
    struct my_dirent sentinel = {0};
    memfd_pwrite(&obj, &sentinel, sizeof(sentinel), pos2);
    int have_dirs = 1;
    while(have_dirs)
    {
        have_dirs = 0;
        struct memfd obj2 = listdirs((void*)obj.buf, &have_dirs);
        memfd_close(&obj);
        obj = obj2;
    }
    return obj;
}

void dump_dirents(struct my_dirent* dirents, int sock)
{
    char* paths = (void*)dirents;
    for(size_t i = 0; dirents[i].path; i++)
    {
        char* path = paths + dirents[i].path;
        size_t l = 0;
        while(path[l])
            l++;
        static const char suffixes[4][11] = {".self", ".sprx", ".elf", "/eboot.bin"};
        int ok = 0;
        for(int i = 0; i < 4 && !ok; i++)
        {
            size_t l2 = 0;
            while(suffixes[i][l2])
                l2++;
            if(l2 > l)
                continue;
            size_t k = l - l2;
            ok = 1;
            for(size_t j = 0; j < l2 && ok; j++)
                if(path[k+j] != suffixes[i][j])
                    ok = 0;
        }
        if(!ok)
            continue;
        struct memfd data = dump_elf(path);
        if(data.size == 0)
        {
            memfd_close(&data);
            continue;
        }
        char tar_header[512] = {0};
        for(size_t i = 0; i < l && i < 99; i++)
            tar_header[i] = path[i+1];
        tar_header[100] = '1';
        tar_header[101] = '0';
        tar_header[102] = '0';
        tar_header[103] = '6';
        tar_header[104] = '4';
        tar_header[105] = '4';
        tar_header[108] = '0';
        tar_header[116] = '0';
        char* p = tar_header + 124;
        for(int i = 30; i >= 0; i -= 3)
            *p++ = (data.size >> i) % 8 + '0';
        tar_header[136] = '0';
        for(int i = 0; i < 8; i++)
            tar_header[148+i] = ' ';
        tar_header[156] = '0';
        uint16_t cksum = 0;
        for(int i = 0; i < 512; i++)
            cksum += (uint8_t)tar_header[i];
        p = tar_header + 148;
        for(int i = 15; i >= 0; i -= 3)
            *p++ = (cksum >> i) % 8 + '0';
        *p++ = 0;
        writeall(sock, tar_header, 512);
        writeall(sock, data.buf, (data.size + 511) & -512);
        memfd_close(&data);
    }
    char tar_end[1024] = {0};
    writeall(sock, tar_end, 1024);
}

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
#ifdef DEBUG
    dbg_enter();
#endif
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
        return 1;
    struct sockaddr_in addr = {
        .sin_family = 2,
        .sin_addr = {0},
        .sin_port = 0x3f23, // ntohs(9023)
    };
    if(bind(sock, (void*)&addr, sizeof(addr))
    || listen(sock, 1))
    {
        close(sock);
        return 1;
    }
    int sock2 = accept(sock, 0, 0);
    if(sock2 < 0)
    {
        close(sock);
        return 1;
    }
    const char* paths[] = {
        "/system_ex",
        "!/decid_update.elf",
        "!/first_img_writer.elf",
        "!/mini-syscore.elf",
        "!/safemode.elf",
        "!/SceSysAvControl.elf",
        "!/setipaddr.elf",
        "/system",
        0
    };
    struct memfd buf = tree(paths);
    dump_dirents((void*)buf.buf, sock2);
    close(sock2);
    kill(getpid(), SIGKILL);
    return 0;
}
