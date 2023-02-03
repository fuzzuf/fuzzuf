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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char expr_s[128];
static int pos;

void crash() { *((unsigned int *)1) = 1; }

void read_file(char *path, char *_buf) {
  FILE *fp;
  if ((fp = fopen(path, "r")) == NULL) {
    fprintf(stderr, "Failed to open %s\n", path);
    exit(EXIT_FAILURE);
  }
  fread(_buf, sizeof(char), 128, fp);
  fclose(fp);
}

static inline int is_num(char c) { return '0' <= c && c <= '9'; }

static int number() {
  int res = 0;
  while (is_num(expr_s[pos])) {
    res *= 10;
    res += expr_s[pos] - '0';
    pos++;
  }
  return res;
}

static int express();
static int fact() {
  if (expr_s[pos] == '(') {
    int res;
    pos++;
    res = express();
    pos++;  // ')'
    return res;
  } else if (is_num(expr_s[pos])) {
    int num = number();
    return num;
  }
  fprintf(stderr, "Unexpected char %c(%d)\n", expr_s[pos], pos);
  exit(0);
}

static int term() {
  int res = fact();
  while (expr_s[pos] == '*' || expr_s[pos] == '/') {
    char op = expr_s[pos];
    pos++;
    if (op == '*') {
      res *= fact();
    } else if (op == '/') {
      int f = fact();
      if (f == 0) {
        fprintf(stderr, "Divided by zero (%d)\n", pos);
        exit(0);
      }
      res /= f;
    }
  }
  return res;
}

static int express() {
  int res = term();
  while (expr_s[pos] == '+' || expr_s[pos] == '-') {
    char op = expr_s[pos];
    pos++;
    if (op == '+') {
      res += term();
    } else if (op == '-') {
      res -= term();
    }
  }
  return res;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage ./calc <input-file>\n");
    exit(EXIT_FAILURE);
  }

  pos = 0;
  memset(expr_s, 0, sizeof(expr_s));

  read_file(argv[1], expr_s);
  printf("Read %s\n", expr_s);
  int res = express();
  if (res != 0 && res % 314 == 0) crash();
  printf("Ans: %d\n", res);
}
