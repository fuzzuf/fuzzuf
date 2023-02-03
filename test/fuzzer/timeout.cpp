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
#define BOOST_TEST_MODULE fuzzer.timeout
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <random>

#include "config.h"
#include "create_file.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/python/python_fuzzer.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "move_to_program_location.hpp"

// Fuzzerインスタンスが適切にPUTへ実行時間制限を課せているか確認

// to test both fork server mode and non fork server mode, we specify forksrv
// via an argument
static void FuzzerTestTimeout(bool forksrv) {
  // cd $(dirname $0)
  MoveToProgramLocation();

  // Create root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  const auto raw_dirname = mkdtemp(root_dir_template.data());
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
  // AddSeedを使うので初期シードは必要ない
  // auto input_path = input_dir / "0";
  // create_file( input_path.string(), "Hello, World!" );

  // Create fuzzer instance
  // sleep 2を制限時間1秒で実行
  auto fuzzer = fuzzuf::bindings::python::PythonFuzzer(
      {"../put_binaries/command_wrapper", "/bin/sleep", "2"},
      input_dir.native(), output_dir.native(), 1000, 10000, forksrv, true,
      true  // need_afl_cov, need_bb_cov
  );

  // Configurate fuzzer
  fuzzer.SuppressLog();

  auto id = fuzzer.AddSeed(
      1, {1});  // どんなシードを与えようがタイムアウトして然るべき
  BOOST_CHECK_EQUAL(
      id,
      fuzzuf::exec_input::ExecInput::
          INVALID_INPUT_ID);  // FIXME:
                              // タイムアウトとクラッシュを識別する手立てがない
}

BOOST_AUTO_TEST_CASE(FuzzerTestTimeoutNonForkMode) {
  // 出力を入れないと、複数テストケースある場合、切れ目がどこかが分からず、どっちが失敗しているか分からない事に気づいた
  std::cout << "[*] FuzzerTestTimeoutNonForkMode started\n";
  FuzzerTestTimeout(false);
  std::cout << "[*] FuzzerTestTimeoutNonForkMode ended\n";
}

BOOST_AUTO_TEST_CASE(FuzzerTestTimeoutForkMode) {
  std::cout << "[*] FuzzerTestTimeoutForkMode started\n";
  FuzzerTestTimeout(true);
  std::cout << "[*] FuzzerTestTimeoutForkMode ended\n";
}
