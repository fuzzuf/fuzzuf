#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

int vulnfunc(int intInput, char * strInput) {
  if (2 * intInput + 1 == 31337) {
    if (strcmp(strInput, "Bad!") == 0)
        abort();
  }
}

int main(int argc, char** argv)
{
  char buf[9];
  int fd;
  size_t n;

  fd = open("input", O_RDONLY);

  if (fd < 0) {
    return -1;
  }

  n = read(fd, buf, sizeof(buf) - 1);
  if (n != sizeof(buf) - 1) {
    return 1;
  }
  buf[8] = 0;

  vulnfunc(*((int32_t*) &buf[0]), &buf[4]);

  return 0;
}

