#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef int (*cmp_fn_t)(const void *, const void *);

struct attack_frame {
    char buf[32];
    cmp_fn_t cmp;
};

static int
safe_cmp(const void *a, const void *b)
{
    int lhs = *(const int *)a;
    int rhs = *(const int *)b;

    puts("safe_cmp()");
    return (lhs > rhs) - (lhs < rhs);
}

static int
evil_cmp(const void *a, const void *b)
{
    (void)a;
    (void)b;

    puts("evil_cmp()");
    return 0;
}

int
main(void)
{
    struct attack_frame frame;
    int values[] = { 3, 1, 2 };

    frame.cmp = safe_cmp;

    puts("poc2: overwrite qsort comparator:");
    fflush(stdout);

    /*
     * The overflow changes only the comparator function pointer passed to libc.
     * The return address stays intact, so shadow-stack checks should not fire first.
     */
    read(STDIN_FILENO, frame.buf, 128);

    qsort(values, sizeof(values) / sizeof(values[0]), sizeof(values[0]), frame.cmp);
    puts("poc2: done");
    return 0;
}
