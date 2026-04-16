#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

void backdoor()
{
    system("/bin/sh");
}

void gadget()
{
    __asm__ __volatile__(
        "pop %rdi; ret;"
        "pop %rsi; ret;"
        "pop %rdx; ret;");
}

int main()
{
    char buffer[64];
    puts("Your input:");
    read(0,buffer,128);
    return 0;
}