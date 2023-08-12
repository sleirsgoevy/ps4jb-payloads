#include "log.h"

uint64_t log[512];
uint64_t* p_log = log;

void log_word(uint64_t word)
{
    if(p_log != log + sizeof(log) / sizeof(*log))
        *p_log++ = word;
}
