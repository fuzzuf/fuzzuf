#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char ** argv){
  signed char c;
  signed short s;
  signed int i;
  int fd;

  if (argc < 2)
    return -1;

  fd = open(argv[1], O_RDWR);

  read(fd, &c, sizeof(c));
  if (0x41 < c && c < 0x65) {
    printf("Found new block 1!\n");
    if (c == 0x53) {
      printf("Found new block 2!\n");
    }
  }

  read(fd, &s, sizeof(s));
  if (0x6162 < s && s < 0x8786) {
    printf("Found new block 3!\n");
    if (s == 0x7172) {
      printf("Found new block 4!\n");
    }
  }

  read(fd, &i, sizeof(i));
  if (0x41424344 < i && i < 0x61626364) {
    printf("Found new block 5!\n");
    if (i == 0x44434241) {
      printf("Found new block 6!\n");
    }
  }

  close(fd);

  return 0;
}
