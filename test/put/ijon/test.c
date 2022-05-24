// Orig: https://github.com/RUB-SysSec/ijon/blob/master/test.c
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define compare(x, y) IJON_CTX(compare_w((x), (y)))
bool compare_w(int x, int y) {
  IJON_CMP(x, y);
  return x == y;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int main(int argc, char** argv) {
#pragma GCC diagnostic pop
  int a = 0;
  int b = 0;
  if (read(0, &a, sizeof(a)) != sizeof(a)) {
    printf("failed to read input\n");
    exit(1);
  } else {
    printf("read %d\n", a);
  }

  if (read(0, &b, sizeof(b)) != sizeof(b)) {
    printf("failed to read input\n");
    exit(1);
  } else {
    printf("read %d\n", b);
  }

  IJON_MAX(a);
  IJON_MAX(b);

  if (a != 0) {
    IJON_CMP(0x4433 % a, 0);
    if (0x4433 % a == 0) IJON_CMP(0x4433 / a, b);
  }
  if (compare(a * b, 0x4433)) {
    assert(false);
  }
}
