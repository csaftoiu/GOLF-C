#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define MAX_RECURSION 1024
#define MAX_HEAP      (64*1024*1024)
#define MAX_STACK     (64*1024*1024)

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#define DATA_START  UINT64_C(0x2000000000000000)
#define STACK_START UINT64_C(0x1000000000000000)
#define HEAP_START  UINT64_C(0x0000000000000000)
#define IO_ADDR     UINT64_C(0xffffffffffffffff)

struct registers
{
    uint64_t a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z;
};

struct registers call_stack_regs[MAX_RECURSION];
void *call_stack_returns[MAX_RECURSION];
size_t call_stack_i = 0;

struct registers regs;

uint8_t *stack, *heap;
%%FILLDATA%%

uint64_t cycles = 0;

void init()
{
    memset(&regs, 0, sizeof(regs));
    regs.z = UINT64_C(0x1000000000000000);

    stack = (uint8_t *)malloc(MAX_STACK);
    heap = (uint8_t *)malloc(MAX_HEAP);
}

void halt(int a)
{
    fprintf(stderr, "Ran for %"PRIu64" cycles\n", cycles);
    exit(a);
}

static inline void mult64to128(uint64_t op1, uint64_t op2, uint64_t *hi, uint64_t *lo)
{
    uint64_t u1 = (op1 & 0xffffffff);
    uint64_t v1 = (op2 & 0xffffffff);
    uint64_t t = (u1 * v1);
    uint64_t w3 = (t & 0xffffffff);
    uint64_t k = (t >> 32);

    op1 >>= 32;
    t = (op1 * v1) + k;
    k = (t & 0xffffffff);
    uint64_t w1 = (t >> 32);

    op2 >>= 32;
    t = (u1 * op2) + k;
    k = (t >> 32);

    *hi = (op1 * op2) + w1 + k;
    *lo = (t << 32) + w3;
}

static inline void store(uint64_t address, uint64_t value, int width)
{
    if (address == IO_ADDR)
    {
        if (width != 8)
        {
            fprintf(stderr, "May only use lw/sw for stdin/stdout");
            exit(1);
        }
        putchar((char)(value & 0xff));
        fflush(stdout);
        return;
    }

    uint8_t *storep;

    if (unlikely(address >= DATA_START))
    {
        fprintf(stderr, "Attempt to store in read-only data section");
        exit(1);
    }
    else if (address >= STACK_START)
    {
        address -= STACK_START;
        if (unlikely(address+width >= MAX_STACK))
        {
            fprintf(stderr, "Store outside of stack");
            exit(1);
        }
        storep = &stack[address];
    }
    else
    {
        if (unlikely(address+width >= MAX_HEAP))
        {
            fprintf(stderr, "Store outside of heap");
            exit(1);
        }
        storep = &heap[address];
    }

    switch (width) {
    case 8: *(storep+7) = (uint8_t)(value >> 56);
            *(storep+6) = (uint8_t)(value >> 48);
            *(storep+5) = (uint8_t)(value >> 40);
            *(storep+4) = (uint8_t)(value >> 32);
    case 4: *(storep+3) = (uint8_t)(value >> 24);
            *(storep+2) = (uint8_t)(value >> 16);
    case 2: *(storep+1) = (uint8_t)(value >>  8);
    case 1: *(storep  ) = (uint8_t)(value      );
    }
}

static inline uint64_t load(uint64_t address, int width)
{
    if (address == IO_ADDR)
    {
        if (width != 8)
        {
            fprintf(stderr, "May only use lw/sw for stdin/stdout");
            exit(1);
        }
        return getchar();
    }

    uint8_t *loadp;

    if (address >= DATA_START)
    {
        address -= DATA_START;
        if (unlikely(address+width >= DATA_LEN))
        {
            fprintf(stderr, "Load outside of data");
            exit(1);
        }
        loadp = &data[address];
    }
    else if (address >= STACK_START)
    {
        address -= STACK_START;
        if (unlikely(address+width >= MAX_STACK))
        {
            fprintf(stderr, "Load outside of stack");
            exit(1);
        }
        loadp = &stack[address];
    }
    else
    {
        if (unlikely(address+width >= MAX_HEAP))
        {
            fprintf(stderr, "Load outside of heap");
            exit(1);
        }
        loadp = &heap[address];
    }

    uint64_t result = 0;
    switch (width) {
    case 8: result += (uint64_t)(*(loadp+7)) << 56;
            result += (uint64_t)(*(loadp+6)) << 48;
            result += (uint64_t)(*(loadp+5)) << 40;
            result += (uint64_t)(*(loadp+4)) << 32;
    case 4: result += (uint64_t)(*(loadp+3)) << 24;
            result += (uint64_t)(*(loadp+2)) << 16;
    case 2: result += (uint64_t)(*(loadp+1)) <<  8;
    case 1: result += (uint64_t)(*(loadp  ))      ;
    }

    return result;
}
