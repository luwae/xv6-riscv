#include "kernel/types.h"
#include "user/user.h"

int f(int);

int main() {
    printf("&main = %p\n", main);
    printf("&f = %p\n", f);
    exit(0);
}

int f(int i) {
    return i + 5;
}
