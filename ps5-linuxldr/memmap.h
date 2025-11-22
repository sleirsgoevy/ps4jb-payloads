#pragma once
#include <stdint.h>
#include <sys/types.h>

struct e820_map_entry
{
    uint64_t start;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

struct memmap_entry;

struct memmap
{
    struct memmap_entry* data;
    size_t size;
    size_t cap;
};

void memmap_add_good_region(struct memmap*, uint64_t start, uint64_t end);
void memmap_add_bad_region(struct memmap*, uint64_t start, uint64_t end);
size_t memmap_emit_e820(struct memmap*, struct e820_map_entry* out, size_t nent);
void memmap_largest_area(struct memmap*, uint64_t* start, uint64_t* end, uint64_t alignment, uint64_t misalignment);
void memmap_copy(struct memmap* dst, struct memmap* src);
void memmap_free(struct memmap*);
