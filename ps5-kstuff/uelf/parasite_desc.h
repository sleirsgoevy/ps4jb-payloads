#include <sys/types.h>

#define PARASITES(n) {\
    int lim_syscall;\
    int lim_fself;\
    int lim_total;\
    struct\
    {\
        uint64_t address;\
        int reg;\
    } parasites[n];\
}

struct parasite_desc PARASITES();
