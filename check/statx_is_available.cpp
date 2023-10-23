#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
  const int dirfd = AT_FDCWD;
  const int flags = AT_SYMLINK_NOFOLLOW;
  const unsigned int mask = STATX_ALL;
  struct statx stxbuf;
  long int ret = statx(dirfd,"./",flags,mask,&stxbuf);
  if( ret < 0 ) std::abort();
}
