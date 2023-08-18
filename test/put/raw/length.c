// A simple example to test whether Eclipser can cooperate well with AFL.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char ** argv){
  int i;
  int fd;
  size_t n;
  char buf[12];

  if (argc < 2)
    return -1;

  fd = open(argv[1], O_RDWR);

  read(fd, &i, sizeof(int));
  if (i == 0x41424344) {
    printf("Found new path 1!\n");
    read(fd, buf, 12);
    n = read(fd, &i, sizeof(int));
    // Input length should be greater than 20 byte for this.
    if (n == sizeof(int)) {
      printf("Found new path 2!\n");
      if (i == 0x61626364) {
        abort();
      }
    }
  }

  close(fd);

  return 0;
}
