#include "memmap.h"
#include <sys/mman.h>

#pragma GCC optimize(3)

struct memmap_entry
{
    uint64_t addr;
    uint32_t kind;
};

void* memcpy(void* dst, const void* src, size_t sz);

static void memmap_push(struct memmap* mm, const struct memmap_entry* e)
{
    if(mm->size == mm->cap)
    {
        size_t new_cap = 2 * mm->cap;
        if(!new_cap)
            new_cap = 16384 / sizeof(*e);
        struct memmap_entry* new_mapping = mmap(0, sizeof(*e) * new_cap, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        memcpy(new_mapping, mm->data, mm->size * sizeof(*e));
        munmap(mm->data, mm->cap * sizeof(*e));
        mm->data = new_mapping;
        mm->cap = new_cap;
    }
    mm->data[mm->size++] = *e;
}

enum
{
    GOOD_START,
    GOOD_END,
    BAD_START,
    BAD_END,
};

void memmap_add_good_region(struct memmap* mm, uint64_t start, uint64_t end)
{
    memmap_push(mm, &(const struct memmap_entry){start, GOOD_START});
    memmap_push(mm, &(const struct memmap_entry){end, GOOD_END});
}

void memmap_add_bad_region(struct memmap* mm, uint64_t start, uint64_t end)
{
    memmap_push(mm, &(const struct memmap_entry){start, BAD_START});
    memmap_push(mm, &(const struct memmap_entry){end, BAD_END});
}

static void swap(struct memmap_entry* a, struct memmap_entry* b)
{
    struct memmap_entry tmp = *a;
    *a = *b;
    *b = tmp;
}

static void sift_up(struct memmap_entry* data, size_t idx)
{
    while(idx > 0 && data[(idx-1)/2].addr < data[idx].addr)
    {
        swap(data+(idx-1)/2, data+idx);
        idx = (idx-1)/2;
    }
}

static size_t sift_down(struct memmap_entry* data, size_t n)
{
    size_t idx = 0;
    for(;;)
    {
        size_t child = 2*idx+1;
        if(child >= n)
            return idx;
        if(child+1 < n && data[child+1].addr > data[child].addr)
            child++;
        swap(data+idx, data+child);
        idx = child;
    }
}

static void heapsort(struct memmap_entry* data, size_t n)
{
    for(size_t i = 0; i < n; i++)
        sift_up(data, i);
    for(size_t i = n-1; i > 0; i--)
    {
        size_t j = sift_down(data, i+1);
        if(i != j)
        {
            swap(data+i, data+j);
            sift_up(data, j);
        }
    }
}

#define ITERATE_MEMMAP(...)\
{\
    heapsort(mm->data, mm->size);\
    int good_depth = 0;\
    int bad_depth = 0;\
    int is_good = 0;\
    uint64_t good_start = 0;\
    size_t i = 0;\
    while(i < mm->size)\
    {\
        uint64_t addr = mm->data[i].addr;\
        while(i < mm->size && mm->data[i].addr == addr)\
        {\
            switch(mm->data[i].kind)\
            {\
            case GOOD_START: good_depth++; break;\
            case GOOD_END: good_depth--; break;\
            case BAD_START: bad_depth++; break;\
            case BAD_END: bad_depth--; break;\
            }\
            i++;\
        }\
        int new_is_good = good_depth && !bad_depth;\
        if(new_is_good && !is_good)\
            good_start = addr;\
        else if(is_good && !new_is_good)\
        {\
            uint64_t start = good_start;\
            uint64_t end = addr;\
            __VA_ARGS__;\
        }\
        is_good = new_is_good;\
    }\
}

size_t memmap_emit_e820(struct memmap* mm, struct e820_map_entry* out, size_t nent)
{
    if(!nent)
        return 0;
    size_t j = 0;
    ITERATE_MEMMAP({
        out[j++] = (struct e820_map_entry){
            .start = start,
            .size = end - start,
            .type = 1,
        };
        if(j == nent)
            return nent;
    });
    return j;
}

void memmap_largest_area(struct memmap* mm, uint64_t* out_start, uint64_t* out_end, uint64_t alignment, uint64_t misalignment)
{
    misalignment = (alignment - misalignment) % alignment;
    *out_start = *out_end = 0;
    ITERATE_MEMMAP({
        start += misalignment;
        start += alignment - 1;
        start -= start % alignment;
        start -= misalignment;
        if(end > start && *out_end - *out_start < end - start)
        {
            *out_start = start;
            *out_end = end;
        }
    });
}

void memmap_copy(struct memmap* dst, struct memmap* src)
{
    if(dst->cap < src->size)
    {
        size_t npages = (sizeof(*src->data) * src->size + 16383) >> 14;
        size_t cap = 16384 * npages / sizeof(*src->data);
        memmap_free(dst);
        dst->data = mmap(0, sizeof(*src->data) * cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        dst->size = src->size;
        dst->cap = cap;
    }
    memcpy(dst->data, src->data, sizeof(*dst->data) * src->size);
    dst->size = src->size;
    return;
}

void memmap_free(struct memmap* mm)
{
    if(mm->data)
        munmap(mm->data, mm->size * sizeof(*mm->data));
    mm->data = 0;
    mm->size = mm->cap = 0;
}
