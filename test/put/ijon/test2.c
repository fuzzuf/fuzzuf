// Orig: https://github.com/RUB-SysSec/ijon/blob/master/test2.c
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
  int o = 200;
  int m = 13;
  printf("a+%d == %d*b (%d == %d)\n", o, m, a + o, b * m);

  IJON_CMP(a + o, 299);
  IJON_DIST(a + o, m * b);

  if (a + o == m * b) {
    assert(false);
  }
}
