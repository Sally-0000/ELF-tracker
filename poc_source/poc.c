#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

typedef void (*fn_t)(void);

static void safe(void)
{
    puts("safe()");
}

static void evil(void)
{
    puts("evil()");
}

int main(void)
{
    struct
    {
        char buf[24];
        fn_t f;
    } frame;
    frame.f = safe;
    puts("input:");
    fflush(stdout);
    read(0, frame.buf, 128);
    frame.f();
    return 0;
}