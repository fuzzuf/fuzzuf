#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int my_strcmp(const char *s1, const char *s2)
{
      for ( ; *s1 == *s2; s1++, s2++)
        if (*s1 == '\0')
          return 0;
        return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
}

int main(int argc, char ** argv) {
  unsigned int i, j;
  char buf[9];
  size_t n;
  int fd;

  if (argc < 2)
    return -1;

  fd = open(argv[1], O_RDWR);

  read(fd, &i, sizeof(i));
  if (i * i == 0x250b6984) // 0x6162 ^ 2
    printf("Found new path 1!\n");

  read(fd, &j, sizeof(j));
  j = ((j >> 24) & 0xff) | // move byte 3 to byte 0
      ((j >> 8) & 0xff00) | // move byte 2 to byte 1
      ((j << 8) & 0xff0000) | // move byte 1 to byte 2
      ((j << 24) & 0xff000000); // byte 0 to byte 3
  if (j * j == 0x10A29504) // 0x4142 ^ 2
    printf("Found new path 2!\n");

  n = read(fd, buf, 8);
  buf[n] = '\0';
  if (my_strcmp(buf, "Good!") == 0)
    printf("Found new path 3!\n");

  if (strcmp(buf, "Bad!") == 0)
    printf("Found new path 4!\n");

  return 0;
}
