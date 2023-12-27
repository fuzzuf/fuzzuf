/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */

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
