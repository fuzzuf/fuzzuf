// A simple example to test whether Eclipser can solve linear branch conditions.
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Initialize '*_const' variables with a separate function, in order to prevent
 * constant propagation optimization
 */
void init_consts(char *c, short* s, int* i, int64_t * i64) {
  *c = 0x61;
  *s = 0x6162;
  *i = 0x61626364;
  *i64 = 0x6162636465666768;
}

int main(int argc, char ** argv){
  char c, c_const;
  short s, s_const;
  int i, i_const, i_be;
  int64_t i64, i64_const;
  int fd;

  if (argc < 2)
    return -1;

  init_consts(&c_const, &s_const, &i_const, &i64_const);

  fd = open(argv[1], O_RDWR);

  read(fd, &c, sizeof(c));
  if (c == 0x41) {
    printf("Found new path 1-1!\n");
  }
  if (c == c_const) { // c_const is 0x61
    printf("Found new path 1-2!\n");
  }

  read(fd, &s, sizeof(short));
  if (s == 0x4142) {
    printf("Found new path 2-1!\n");
  }
  if (s == s_const) { // s_const is 0x6162
    printf("Found new path 2-2!\n");
  }

  read(fd, &i, sizeof(int));
  if (i == 0x41424344) {
    printf("Found new path 3-1!\n");
  }
  if (i == i_const) { // i_const is 0x61626364
    printf("Found new path 3-2!\n");
  }

  read(fd, &i64, sizeof(int64_t));
  if (i64 == 0x4142434445464748ll) {
    printf("Found new path 4-1!\n");
  }
  if (i64 == i64_const) { // i64_const is 0x6162636465666768
    printf("Found new path 4-2!\n");
  }

  i_be = ((i >> 24) & 0xff) | // move byte 3 to byte 0
         ((i >> 8) & 0xff00) | // move byte 2 to byte 1
         ((i << 8) & 0xff0000) | // move byte 1 to byte 2
         ((i << 24)& 0xff000000); // byte 0 to byte 3

  if (i_be == 0x71727374) {
    printf("Found new path 5!\n");
  }

  close(fd);

  return 0;
}
