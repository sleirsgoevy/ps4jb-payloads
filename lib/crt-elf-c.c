#include <sys/types.h>

struct specter_args
{
    void* dlsym;
    int* pipe;
    int* rwpair;
    uint64_t kpipe_addr;
    uint64_t kdata_base;
    int* retval;
};

uint64_t _start(void* dlsym, int master, int victim, uint64_t pktopts, uint64_t kdata_base);

void elf_main(struct specter_args* args)
{
    *args->retval = _start(args->dlsym, args->rwpair[0], args->rwpair[1], 0, args->kdata_base);
}
