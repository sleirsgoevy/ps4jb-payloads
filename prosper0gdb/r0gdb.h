#pragma once
#include <sys/types.h>

/* krw utils */

uint64_t kread8(uint64_t ptr);
int kwrite20(uint64_t ptr, uint64_t a, uint64_t b, uint32_t c);
uint64_t kmalloc(int sz);
int kfree(uint64_t ptr);
ssize_t copyout(void* dst, uint64_t src, size_t count);
ssize_t copyin(uint64_t dst, const void* src, size_t count);

/* init */

//call before everything
void r0gdb_init(void* ds, int a, int b, uintptr_t c, uintptr_t d);

//set up for interactive gdb
void r0gdb_setup(int do_swapgs);

//set up for trace capture
void r0gdb_trace(size_t trace_size);

//set up for instrumentation
void r0gdb_instrument(size_t trace_size);

//call from kernel gdb to exit
void r0gdb_exit(void);

//call to enter kernel gdb
void r0gdb(void);

//rdmsr & wrmsr (after r0gdb_setup only)
uint64_t r0gdb_rdmsr(uint32_t ecx);
void r0gdb_wrmsr(uint32_t ecx, uint64_t value);

//netcat captured trace to specified ip & port
int r0gdb_trace_send(const char* ipaddr, int port);

//clear captured trace
void r0gdb_trace_reset(void);

/* utils */

//mprotect with disabled permission checks
int mprotect20(void* addr, size_t sz, int prot);

//mmap with map_self
void* mmap20(void* addr, size_t sz, int prot, int flags, int fd, off_t offset);

//kernel function call
uint64_t r0gdb_kfncall(uint64_t kfn, ...);

//kernel malloc via function call
uint64_t r0gdb_kmalloc(size_t sz);

/* internals */

extern uint64_t kstack;
extern uint64_t kframe;
extern uint64_t uretframe;

extern uint64_t trace_base;
extern uint64_t trace_start;
extern uint64_t trace_end;
extern void(*trace_prog)(uint64_t*);
