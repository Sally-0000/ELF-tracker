#include <stdio.h>

void vuln() {
    char buf[128];
    read(0, buf, 256);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("Enter some text: ");
    vuln();
    printf("Hello, World!\n");
    return 0;
}