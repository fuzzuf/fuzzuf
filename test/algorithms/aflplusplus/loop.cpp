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
#define BOOST_TEST_MODULE aflplusplus.loop
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <random>

#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "move_to_program_location.hpp"

// to test both fork server mode and non fork server mode, we specify forksrv
// via an argument
static void AFLLoop(bool forksrv) {
  // cd $(dirname $0)
  MoveToProgramLocation();

  // Create root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  const auto raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);

  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) {
    // Executed on this test exit
    fs::remove_all(root_dir);
  }
  BOOST_SCOPE_EXIT_END

  // Create input file
  auto put_dir = fs::path("../../put_binaries/libjpeg");
  auto input_dir = put_dir / "seeds";
  auto output_dir = root_dir / "output";

  auto input_dir_opt = "--in_dir=" + input_dir.string();
  auto output_dir_opt = "--out_dir=" + output_dir.string();
  const char *forksrv_opt = forksrv ? "--forksrv=1" : "--forksrv=0";

  const char *argv[] = {"fuzzuf",
                        "aflplusplus",
                        input_dir_opt.c_str(),
                        output_dir_opt.c_str(),
                        forksrv_opt,
                        "../../put_binaries/libjpeg/libjpeg_turbo_fuzzer",
                        "@@",
                        nullptr};
  int argc = static_cast<int>(sizeof(argv) / sizeof(const char *)) -
             1;  // subtract 1 for nullptr
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);

  for (int i = 0; i < 1; i++) {
    std::cout << "the " << i << "-th iteration starts" << std::endl;
    fuzzer->OneLoop();
  }
}

BOOST_AUTO_TEST_CASE(AFLLoopNonForkMode) {
  // 出力を入れないと、複数テストケースある場合、切れ目がどこかが分からず、どっちが失敗しているか分からない事に気づいた
  std::cout << "[*] AFLLoopNonForkMode started\n";
  AFLLoop(false);
  std::cout << "[*] AFLLoopNonForkMode ended\n";
}

BOOST_AUTO_TEST_CASE(AFLLoopForkMode) {
  std::cout << "[*] AFLLoopForkMode started\n";
  AFLLoop(true);
  std::cout << "[*] AFLLoopForkMode ended\n";
}
