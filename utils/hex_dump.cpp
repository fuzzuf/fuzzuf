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
/**
 * @file hex_dump.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/hex_dump.hpp"

#include <assert.h>
#include <stdio.h>

namespace fuzzuf::utils {
// ファイルポインタ fp で指定されたストリームに、バッファ buf のオフセット
// offset から len バイトだけHex Dumpしてくれる便利関数 offset
// は16の倍数にしてください。でないとi+jのせいで壊れます
// FIXME: 暗黙のLinux前提
void HexDump(FILE* fp, unsigned char* buf, size_t len, size_t offset) {
  assert(buf);
  fprintf(fp, "(size = %#lx)\n", len);
  size_t end = offset + len;
  for (size_t i = offset; i < end; i += 0x10) {
    fprintf(fp, "%08lx: ", i / 0x10 * 0x10);
    for (int j = 0; j < 0x10 && i + j < end; j += 1) {
      fprintf(fp, "%02x ", buf[i + j]);
      if (j == 7) fprintf(fp, "   ");
    }
    fprintf(fp, "\n");
  }
}
}  // namespace fuzzuf::utils
