#include <stdio.h>

int global_var = 42;

struct Point {
    int x;
    int y;
};

int add(int a, int b) {
    int result = a + b;
    return result;
}

int main() {
    struct Point p = {10, 20};
    int local_var = 100;
    int sum = add(p.x, p.y);
    printf("Sum: %d\n", sum);
    return 0;
}