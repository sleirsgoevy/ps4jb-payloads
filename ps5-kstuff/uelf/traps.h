#pragma once

enum
{
    TRAP_UTILS = 0xdead0000,
    TRAP_KEKCALL,
    TRAP_FSELF,
    TRAP_FPKG,
};

#define MKTRAP(kind, idx) (((uint64_t)(kind) << 32) | ((uint64_t)(idx)))
#define TRAP_KIND(kind) ((uint32_t)((kind) >> 32))
#define TRAP_IDX(kind) ((uint32_t)(kind))
