#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char ** argv){
  short s;
  int i1, i2, i3, j;
  int fd;
  int n;

  if (argc < 2)
    return -1;

  fd = open(argv[1], O_RDWR);

  read(fd, &i1, sizeof(int));
  read(fd, &i2, sizeof(int));
  read(fd, &i3, sizeof(int));

  if (i1 == 0x41424344) {
    printf("Found new path 1!\n");
  }

  for (j = 0; j < i2; j++) {
    n += j;
  }

  if (i3 == 0x61626364) {
    printf("Found new path 2!\n");
  }

  close(fd);

  return 0;
}
