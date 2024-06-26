#include <stdio.h>

void foo(void) {
    printf("im in foo.\n");
}

int main(int argc, char const *argv[]) {
    printf("hello world.\n");
    int a = 1;
    if (a)
        foo();
    return 0;
}
