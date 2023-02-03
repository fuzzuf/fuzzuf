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
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef __linux__
#define HAVE_AFFINITY 1
#endif /* __linux__ */

/************************
 * Debug & error macros *
 ************************/

/* Show a prefixed warning. */

#define WARNF(x...)                           \
  do {                                        \
    MSG(cYEL "[!] " cBRI "WARNING: " cRST x); \
    MSG(cRST "\n");                           \
  } while (0)

/* Show a prefixed "doing something" message. */

#define ACTF(x...)           \
  do {                       \
    MSG(cLBL "[*] " cRST x); \
    MSG(cRST "\n");          \
  } while (0)

/* Show a prefixed "success" message. */

#define OKF(x...)            \
  do {                       \
    MSG(cLGN "[+] " cRST x); \
    MSG(cRST "\n");          \
  } while (0)

/* Show a prefixed fatal error message (not used in afl). */

#define BADF(x...)             \
  do {                         \
    MSG(cLRD "\n[-] " cRST x); \
    MSG(cRST "\n");            \
  } while (0)
