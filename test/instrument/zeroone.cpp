/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
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
#include <cstdio>

#define IFBRANCH(buf, idx, var) \
  if (buf[idx] == '1') {        \
    var = 1;                    \
  } else {                      \
    var = 0;                    \
  }

int main() {
  char buf[256];
  fgets(buf, sizeof(buf), stdin);

  volatile int a, b, c, d, e, f, g, h;

  // do not put this into loop because we want to see control flow graph
  IFBRANCH(buf, 0, a);
  IFBRANCH(buf, 1, b);
  IFBRANCH(buf, 2, c);
  IFBRANCH(buf, 3, d);
  IFBRANCH(buf, 4, e);
  IFBRANCH(buf, 5, f);
  IFBRANCH(buf, 6, g);
  IFBRANCH(buf, 7, h);

  printf("Result: %d%d%d%d%d%d%d%d\n", a, b, c, d, e, f, g, h);
}
