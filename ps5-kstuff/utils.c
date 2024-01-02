#define sysctl __sysctl
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/thr.h>
#include <sys/sysctl.h>
#include <machine/sysarch.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <signal.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include "../prosper0gdb/r0gdb.h"
#include "../gdb_stub/dbg.h"

extern uint64_t kdata_base;

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

int find_proc(const char* name);

void list_proc(void)
{
    for(int pid = 1; pid < 1024; pid++)
    {
        size_t sz = 1096;
        int key[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        char buf[1097] = {0};
        sysctl(key, 4, buf, &sz, 0, 0);
        char* name = buf + 447;
        if(!*name)
            continue;
        *--name = ' ';
        for(int q = pid; q; q /= 10)
            *--name = '0' + q % 10;
        size_t l = 0;
        while(name[l])
            l++;
        name[l++] = '\n';
        gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)name, (uintptr_t)l);
    }
}

#define KEKCALL_GETPPID        0x000000027
#define KEKCALL_READ_DR        0x100000027
#define KEKCALL_WRITE_DR       0x200000027
#define KEKCALL_RDMSR          0x300000027
#define KEKCALL_REMOTE_SYSCALL 0x500000027
#define KEKCALL_CHECK          0xffffffff00000027

asm(".section .text\nkekcall:\nmov 8(%rsp), %rax\njmp *p_kekcall(%rip)");
uint64_t kekcall(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t nr);

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

static uint64_t shellcore_args_base;

struct shellcore_patch
{
    uint64_t offset;
    char* data;
    size_t sz;
};

uint64_t get_eh_frame_offset(const char* path);

static void temp_patch_shellcore(struct shellcore_patch* sc_patches, int n_patches, int do_lk)
{
    int pid = find_proc("SceShellCore");
    struct module_info_ex mod_info;
    mod_info.st_size = sizeof(mod_info);
    do_remote_syscall(pid, SYS_dynlib_get_info_ex, 0, 0, &mod_info);
    uint64_t shellcore_base = mod_info.eh_frame_hdr_addr - get_eh_frame_offset("/system/vsh/SceShellCore.elf");
    mod_info.st_size = sizeof(mod_info);
    uint64_t libkernel_nmount;
    do_remote_syscall(pid, SYS_dynlib_dlsym, 0x2001, "nmount", &libkernel_nmount);
    shellcore_args_base = do_remote_syscall(pid, SYS_mmap, 0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    struct
    {
        uint64_t addr;
        void* data;
        size_t sz;
    } patches[] = {
        {libkernel_nmount, "\x48\xb8\xef\xbe\xad\xde\xef\xbe\xad\xde\x48\x89\x38\x48\x89\x70\x08\x48\x89\x50\x10\xeb\xfe", do_lk ? 23 : 0},
        {libkernel_nmount+2, &shellcore_args_base, do_lk ? 8 : 0},
    };
    for(int i = 0; i < n_patches; i++)
    {
        uint64_t arg1[4] = {1, 0x13};
        uint64_t arg2[8] = {pid, shellcore_base+sc_patches[i].offset, (uint64_t)sc_patches[i].data, sc_patches[i].sz};
        uint64_t arg3[4] = {0};
        mdbg_call_20(arg1, arg2, arg3);
    }
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
    uint64_t* ptrs = mmap(0, sizeof(*ptrs) * args[1] * 2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    READ(ptrs, args[0], sizeof(*ptrs) * args[1] * 2);
    for(int i = 0; i < args[1]; i++)
    {
        uint64_t ptr = ptrs[2*i];
        uint64_t sz = ptrs[2*i+1];
        char* buf = mmap(0, sz+1, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
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
