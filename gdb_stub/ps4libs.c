#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#undef errno
extern int errno;

typedef unsigned char pkt_opaque[1];

typedef struct srv_opaque
{
    unsigned long long offset;
    unsigned long long len;
    int nonempty;
} srv_opaque[1];

void serve_genfn_start(pkt_opaque, srv_opaque, int);
int serve_genfn_emit(pkt_opaque, srv_opaque, const char*, unsigned long long);
void serve_genfn_end(pkt_opaque, srv_opaque);

int randomized_path(unsigned long long, char*, size_t*);

static int get_elf_offsets(const char* name, unsigned long long* addrs)
{
    size_t o = 0;
    while(name[o])
        o++;
    char path[o + sizeof("/0123456789/common/lib/")];
    for(size_t i = 0; i < sizeof("/system/common/lib/"); i++)
        path[i] = "/system/common/lib/"[i];
    for(size_t i = 0; i <= o; i++)
        path[i + sizeof("/system/common/lib/") - 1] = name[i];
    int fd = open(path, O_RDONLY);
    if(fd < 0) // sandboxed
    {
        char sandbox_path[11];
        size_t sz = 11;
        if(randomized_path(0, sandbox_path, &sz))
            return -1;
        path[0] = '/';
        for(size_t i = 0; i < 10; i++)
            path[i+1] = sandbox_path[i];
        for(size_t i = 0; i < sizeof("/common/lib/"); i++)
            path[i+11] = "/common/lib/"[i];
        for(size_t i = 0; i <= o; i++)
            path[i + sizeof("/0123456789/common/lib/") - 1] = name[i];
        fd = open(path, O_RDONLY);
        if(fd < 0)
        {
            char path_app0[o + sizeof("/app0/sce_module/")];
            for(size_t i = 0; i < sizeof("/app0/"); i++)
                path_app0[i] = "/app0/"[i];
            for(size_t i = 0; i <= o; i++)
                path_app0[i + sizeof("/app0/") - 1] = name[i];
            fd = open(path_app0, O_RDONLY);
            if(fd < 0)
            {
                for(size_t i = 0; i < sizeof("/app0/sce_module/"); i++)
                    path_app0[i] = "/app0/sce_module/"[i];
                for(size_t i = 0; i <= o; i++)
                    path_app0[i + sizeof("/app0/sce_module/") - 1] = name[i];
                fd = open(path_app0, O_RDONLY);
                if(fd < 0)
                    return -1;
            }
        }
    }
    unsigned long long shit[4];
    if(read(fd, shit, sizeof(shit)) != sizeof(shit))
    {
        close(fd);
        return -1;
    }
    off_t o2 = 0x20*((shit[3]&0xffff)+1);
    lseek(fd, o2, SEEK_SET);
    unsigned long long ehdr[8];
    if(read(fd, ehdr, sizeof(ehdr)) != sizeof(ehdr))
    {
        close(fd);
        return -1;
    }
    off_t phdr_offset = o2 + ehdr[4];
    int nphdr = ehdr[7] & 0xffff;
    unsigned long long eh_frame = -1;
    unsigned long long dynamic = -1;
    lseek(fd, phdr_offset, SEEK_SET);
    for(int i = 0; i < nphdr; i++)
    {
        unsigned long long phdr[7];
        if(read(fd, phdr, sizeof(phdr)) != sizeof(phdr))
        {
            close(fd);
            return -1;
        }
        unsigned long long addr = phdr[2];
        int ptype = phdr[0] & 0xffffffff;
        if(ptype == 2)
            dynamic = addr;
        else if(ptype == 0x6474e550)
            eh_frame = addr;
    }
    close(fd);
    if(dynamic == -1 || eh_frame == -1)
        return -1;
    addrs[0] = eh_frame;
    addrs[1] = dynamic;
    return 0;
}

static int handle_lib(pkt_opaque o, srv_opaque p, const char* name, unsigned long long eh_frame)
{
    size_t l = 0;
    while(name[l])
        l++;
    unsigned long long ptrs[2];
    if(get_elf_offsets(name, ptrs))
        return -1;
    unsigned long long base = eh_frame - ptrs[0];
    unsigned long long dyn = base + ptrs[1];
    serve_genfn_emit(o, p, "<library name=\"", 15);
    serve_genfn_emit(o, p, name, l);
    char buf[] = "\" l_addr=\"0xXXXXXXXXXXXX\" lm=\"0\" l_ld=\"0xXXXXXXXXXXXX\"/>";
    for(int i = 0; i < 12; i++)
    {
        buf[i + 12] = "0123456789abcdef"[(base >> (44 - 4 * i)) & 15];
        buf[i + 41] = "0123456789abcdef"[(dyn >> (44 - 4 * i)) & 15];
    }
    serve_genfn_emit(o, p, buf, sizeof(buf) - 1);
    return 0;
}

int dynlib_get_list(uint32_t* handles, size_t num, size_t* actual_num);

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

int dynlib_get_info_ex(uint32_t handle, int unknown, struct module_info_ex* info);

int try_list_libs(pkt_opaque o, srv_opaque p, size_t sz)
{
    uint32_t handles[sz];
    size_t nlibs = sz;
    if(dynlib_get_list(handles, sz, &nlibs))
    {
        if(errno == ENOMEM)
            return 1;
        return -1;
    }
    for(size_t i = 0; i < nlibs; i++)
    {
        struct module_info_ex ex;
        ex.st_size = sizeof(ex);
        if(dynlib_get_info_ex(handles[i], 0, &ex))
            continue;
        handle_lib(o, p, ex.name, ex.eh_frame_hdr_addr);
    }
    return 0;
}

void list_libs(pkt_opaque o)
{
    srv_opaque p;
    serve_genfn_start(o, p, 1);
    serve_genfn_emit(o, p, "<library-list-svr4 version=\"1.0\">", 33);
    size_t nlibs = 1;
    int ret;
    while((ret = try_list_libs(o, p, nlibs)) == 1)
        nlibs *= 2;
    serve_genfn_emit(o, p, "</library-list-svr4>", 20);
    serve_genfn_end(o, p);
}

void kexec(void*, void*);
asm("kexec:\nmov $11,%rax\nmov %rcx, %r10\nsyscall\nret");

static void k_set_budget(int** td, int** uap)
{
    int tmp = uap[1][0];
    uap[1][0] = td[1][701];
    td[1][701] = tmp;
}

void ps4_xchg_budget(int* bb)
{
    kexec(k_set_budget, bb);
}
