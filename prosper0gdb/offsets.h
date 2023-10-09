#pragma once
#include <stdint.h>

struct offset_table
{
#define OFFSET(x) uint64_t x;
#include "offset_list.txt"
#undef OFFSET
};

extern struct offset_table offsets;
