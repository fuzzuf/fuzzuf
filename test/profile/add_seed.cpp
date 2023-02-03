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
#include <boost/scope_exit.hpp>
#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "config.h"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/python/python_fuzzer.hpp"
#include "fuzzuf/utils/filesystem.hpp"

int main(int argc, char **argv) {
  srand(time(NULL));
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;

  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  fs::create_directory(input_dir);

  std::vector<std::string> argvv;
  if (argc < 3 || (strcmp(argv[1], "0") != 0 && strcmp(argv[1], "1") != 0)) {
    printf(
        "[ usage ] %s (0, 1: non-fork-server-mode, fork-server-mode) <argv>\n",
        argv[0]);
    printf("ex) %s 1 /Bench/freetype/ftfuzzer @@\n", argv[0]);
    return 1;
  }
  for (int i = 2; i < argc; i++) {
    argvv.emplace_back(argv[i]);
  }
  auto fuzzer = fuzzuf::bindings::python::PythonFuzzer(
      argvv, input_dir.native(), output_dir.native(), 100, 10000,
      argv[1][0] == '1',  // forksrv
      true, true          // need_afl_cov, need_bb_cov
  );
  fuzzer.SuppressLog();
  std::vector<u8> my_buf;
  auto LEN = 10000;
  for (int i = 0; i < LEN; i++) {
    my_buf.push_back(rand() % 256);
  }
  for (int i = 0; i < 20000; i++) {
    if (i % 10000 == 0 && i) {
      printf("finished %d add_seed\n", i);
    }
    auto id = fuzzer.AddSeed(LEN, my_buf);
    if (id != fuzzuf::exec_input::ExecInput::INVALID_INPUT_ID) {
      fuzzer.RemoveSeed(id);
    }
  }
}
