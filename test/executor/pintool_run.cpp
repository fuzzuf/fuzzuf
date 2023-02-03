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
#define BOOST_TEST_MODULE pintool_executor.run
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <move_to_program_location.hpp>

#include "config.h"
#include "fuzzuf/executor/pintool_executor.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

// PinToolExecutor::Run() の正常系テスト
BOOST_AUTO_TEST_CASE(PinToolExecutorRun) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);

  // bbcounts2がカレントディレクトリを汚すので
  // テスト後に削除されるディレクトリに移動
  fs::current_path(root_dir);

  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  BOOST_CHECK_EQUAL(setenv("FUZZUF_BBCOUNTS2_OUTDIR", output_dir.c_str(), 1),
                    0);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::PinToolExecutor executor(
      FUZZUF_PIN_EXECUTABLE,
      {TEST_BINARY_DIR "/../tools/bbcounts2/bbcounts2.so", "-o", "bb.out",
       "-libc", "0"},
      {"/usr/bin/tee", output_file_path.native()}, 0, 0, path_to_write_seed);

  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke PinToolExecutor::Run()
  size_t INPUT_LENGTH = 14;
  std::string input("Hello, World!");
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());

  // Check normality
  // (1) 正常実行されたこと → feedbackのexit_reason が
  // fuzzuf::feedback::PUTExitReasonType::FAULT_NONE であることを確認する
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_NONE);

  // (2) 標準入力によってファズが受け渡されたこと →
  // 標準入力と同じ内容がファイルに保存されたことを確認する
  BOOST_CHECK(fs::exists(output_file_path));
  BOOST_CHECK_EQUAL(fs::file_size(output_file_path), input.length());
  int output_file =
      fuzzuf::utils::OpenFile(output_file_path.native(), O_RDONLY);
  BOOST_CHECK_LE(input.length(), INPUT_LENGTH);
  char output_file_buf[INPUT_LENGTH];
  BOOST_CHECK_GT(output_file, -1);
  fuzzuf::utils::ReadFile(output_file, static_cast<void *>(output_file_buf),
                          input.length());
  BOOST_CHECK_EQUAL(
      strncmp(output_file_buf, reinterpret_cast<const char *>(input.c_str()),
              input.length()),
      0);

  fuzzuf::utils::CloseFile(output_file);
}
