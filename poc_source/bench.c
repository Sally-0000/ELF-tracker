#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int (*fp_fn_t)(int);

static volatile int g_sink = 0;

static uint64_t
now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

__attribute__((noinline))
static int
hot_target(int x)
{
    return x + 1;
}

__attribute__((noinline))
static int
bench_cmp(const void *lhs, const void *rhs)
{
    int a = *(const int *)lhs;
    int b = *(const int *)rhs;

    return (a > b) - (a < b);
}

static int
run_fp_bench(uint64_t iterations)
{
    volatile fp_fn_t fn = hot_target;
    uint64_t i;
    int acc = 0;

    for (i = 0; i < iterations; ++i)
        acc += fn((int)i);

    g_sink = acc;
    return acc;
}

static int
run_qsort_bench(uint64_t iterations)
{
    uint64_t i;
    int acc = 0;

    for (i = 0; i < iterations; ++i) {
        int values[8] = { 8, 3, 5, 1, 7, 4, 6, 2 };
        qsort(values, sizeof(values) / sizeof(values[0]), sizeof(values[0]), bench_cmp);
        acc += values[0];
    }

    g_sink = acc;
    return acc;
}

int
main(int argc, char **argv)
{
    const char *mode;
    uint64_t iterations;
    uint64_t begin_ns;
    uint64_t end_ns;
    int result;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <fp|qsort> <iterations>\n", argv[0]);
        return 1;
    }

    mode = argv[1];
    iterations = strtoull(argv[2], NULL, 10);
    if (iterations == 0) {
        fprintf(stderr, "iterations must be > 0\n");
        return 1;
    }

    begin_ns = now_ns();
    if (strcmp(mode, "fp") == 0) {
        result = run_fp_bench(iterations);
    } else if (strcmp(mode, "qsort") == 0) {
        result = run_qsort_bench(iterations);
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 1;
    }
    end_ns = now_ns();

    printf("mode=%s iterations=%llu elapsed_ns=%llu result=%d\n",
           mode,
           (unsigned long long)iterations,
           (unsigned long long)(end_ns - begin_ns),
           result);
    return 0;
}
