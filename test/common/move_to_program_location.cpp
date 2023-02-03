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
#include <boost/test/unit_test.hpp>
#include <cassert>

#include "fuzzuf/utils/filesystem.hpp"

// shell scriptでいうところのcd $(dirname $0)するための関数。
// テストコード中で使用するとどのcwdからテストのバイナリを実行しても動作するようになるはず
void MoveToProgramLocation(void) {
  static bool has_moved = false;

  if (has_moved) return;
  has_moved = true;

  char *argv0 = boost::unit_test::framework::master_test_suite().argv[0];
  assert(argv0);

  fs::current_path(fs::path(argv0).parent_path());
}
