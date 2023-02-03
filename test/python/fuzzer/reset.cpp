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
#define BOOST_TEST_MODULE fuzzerhandle.reset
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <create_file.hpp>
#include <iostream>
#include <random>

#include "config.h"
#include "fuzzuf/python/python_fuzzer.hpp"
#include "fuzzuf/utils/filesystem.hpp"

// PythonFuzzer::Resetが正常に実行されることを確認する
// to test both fork server mode and non fork server mode, we specify forksrv
// via an argument
static void PythonFuzzerReset(bool forksrv) {
  // Create root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
#ifdef HAS_CXX_STD_FILESYSTEM
  namespace fs = std::filesystem;
#else
  namespace fs = boost::filesystem;
#endif
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) {
    // Executed on this test exit
    fs::remove_all(root_dir);
  }
  BOOST_SCOPE_EXIT_END

  // Create input file
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  auto input_path = input_dir / "0";
  create_file(input_path.string(), "Hello, World!");

  // Create fuzzer instance
  auto fuzzer = fuzzuf::bindings::python::PythonFuzzer(
      {"../../put_binaries/command_wrapper", "/bin/cat"}, input_dir.native(),
      output_dir.native(), 1000, 10000, forksrv, true,
      true  // need_afl_cov, need_bb_cov
  );

  // Configurate fuzzer
  fuzzer.SuppressLog();

  // 初期シードが1つだけ存在しているはず
  auto seed_ids = fuzzer.GetSeedIDs();
  BOOST_CHECK_EQUAL(seed_ids.size(), 1);
  auto seed_id = seed_ids[0];

  std::mt19937 rand;
  std::uniform_int_distribution<> len_dist(0, 2);
  for (int i = 0; i != 100; ++i) {
    fuzzer.SelectSeed(seed_id);
    auto len = 1 << (len_dist(rand));
    std::uniform_int_distribution<> pos_dist(0, 12 * 8 - len);
    fuzzer.FlipBit(pos_dist(rand), len);
  }

  // /bin/catは流石にどんなシードを与えられてもクラッシュはしないので、
  // 100回mutationすると初期シードも合わせて101個シードがあるべき
  seed_ids = fuzzer.GetSeedIDs();
  BOOST_CHECK_EQUAL(seed_ids.size(), 101);

  fuzzer.Reset();

  // 初期シードが1つだけ存在しているはず
  seed_ids = fuzzer.GetSeedIDs();
  BOOST_CHECK_EQUAL(seed_ids.size(), 1);
  seed_id = seed_ids[0];

  // Reset後、mutation & Executor::Runしてもクラッシュしない
  for (int i = 0; i != 100; ++i) {
    fuzzer.SelectSeed(seed_id);
    auto len = 1 << (len_dist(rand));
    std::uniform_int_distribution<> pos_dist(0, 12 * 8 - len);
    fuzzer.FlipBit(pos_dist(rand), len);
  }
}

BOOST_AUTO_TEST_CASE(PythonFuzzerResetNonForkMode) {
  // 出力を入れないと、複数テストケースある場合、切れ目がどこかが分からず、どっちが失敗しているか分からない事に気づいた
  std::cout << "[*] PythonFuzzerResetNonForkMode started\n";
  PythonFuzzerReset(false);
  std::cout << "[*] PythonFuzzerResetNonForkMode ended\n";
}

BOOST_AUTO_TEST_CASE(PythonFuzzerResetForkMode) {
  std::cout << "[*] PythonFuzzerResetForkMode started\n";
  PythonFuzzerReset(true);
  std::cout << "[*] PythonFuzzerResetForkMode ended\n";
}
