#include "../gdb_stub/dbg.h"
#include "r0gdb.h"
#include <stdint.h>

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    r0gdb_init(ds, a, b, c, d);
    dbg_enter();
    return 0; //p r0gdb() for magic
}
