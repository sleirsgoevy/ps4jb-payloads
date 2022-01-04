#pragma once

void dbg_enter(void);
long gdb_remote_syscall(const char* name, int nargs, int* ern, ...);
