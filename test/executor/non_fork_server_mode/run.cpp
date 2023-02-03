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
#define BOOST_TEST_MODULE native_linux_executor.run
#define BOOST_TEST_DYN_LINK

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/which.hpp"

// NativeLinuxExecutor::Run() の正常系テスト
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRun) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {fuzzuf::utils::which(fs::path("tee")).c_str(),
       output_file_path.native()},
      1000, 10000, false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE, true);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
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

  auto stdout_buffer_feedback = executor.GetStdOut();
  stdout_buffer_feedback.ShowMemoryToFunc([](const u8 *ptr, u32 len) {
    std::vector<std::uint8_t> expected_stdout{'H', 'e', 'l', 'l', 'o', ',', ' ',
                                              'W', 'o', 'r', 'l', 'd', '!'};

    BOOST_CHECK_EQUAL_COLLECTIONS(ptr, ptr + len, expected_stdout.begin(),
                                  expected_stdout.end());
  });
  fuzzuf::feedback::InplaceMemoryFeedback::DiscardActive(
      std::move(stdout_buffer_feedback));

  auto stderr_buffer_feedback = executor.GetStdErr();
  stderr_buffer_feedback.ShowMemoryToFunc([](const u8 *ptr, u32 len) {
    std::vector<std::uint8_t> expected_stderr{};

    BOOST_CHECK_EQUAL_COLLECTIONS(ptr, ptr + len, expected_stderr.begin(),
                                  expected_stderr.end());
  });
  fuzzuf::feedback::InplaceMemoryFeedback::DiscardActive(
      std::move(stderr_buffer_feedback));

  // (3) Check if executor correctly clears stdout_buffer before a new
  // execution. Otherwise the output from stdout during the previous execution
  // should remain in stdout_buffer.
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());

  stdout_buffer_feedback = executor.GetStdOut();
  stdout_buffer_feedback.ShowMemoryToFunc([](const u8 *ptr, u32 len) {
    std::vector<std::uint8_t> expected_stdout{'H', 'e', 'l', 'l', 'o', ',', ' ',
                                              'W', 'o', 'r', 'l', 'd', '!'};

    BOOST_CHECK_EQUAL_COLLECTIONS(ptr, ptr + len, expected_stdout.begin(),
                                  expected_stdout.end());
  });
}

// 正常終了するプロセスがFAULT_NONEになることを確認する
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunOk) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      //{ "/usr/bin/tee", output_file_path.native() },
      {TEST_BINARY_DIR "/executor/ok", output_file_path.native()}, 1000, 10000,
      false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_NONE);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, 0);
}

// 異常終了(非ゼロな引数によるexit)するプロセスがFAULT_NONEになることを確認する
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunFail) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_BINARY_DIR "/executor/fail", output_file_path.native()}, 1000,
      10000, false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_NONE);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, 0);
}

// Check if NativeLinuxExecutor can time out an execution of a PUT without going
// into a busy loop even if the PUT infinitely outputs strings.
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunTooMuchOutput,
                     *boost::unit_test::timeout(2)) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");

  const auto raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);

  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_BINARY_DIR "/executor/too_much_output"}, 1000, 10000, false,
      path_to_write_seed, PAGE_SIZE, PAGE_SIZE, true /* record_stdout_and_err */
  );
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_TMOUT);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, SIGKILL);
}

// abort()するプロセスがFAULT_CRASHになることを確認する
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunAbort) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_BINARY_DIR "/executor/abort", output_file_path.native()}, 1000,
      10000, false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_CRASH);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, SIGABRT);
}

// segmentaton faultするプロセスがFAULT_CRASHになることを確認する
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunSegmentationFault) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_BINARY_DIR "/executor/segmentation_fault",
       output_file_path.native()},
      1000, 10000, false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_CRASH);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, SIGSEGV);
}

// 終了しないプロセスがFAULT_TMOUTになることを確認する
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunNeverExit) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_BINARY_DIR "/executor/never_exit", output_file_path.native()}, 1000,
      10000, false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_TMOUT);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, SIGKILL);
}

// 存在しない実行可能バイナリの実行がFAULT_ERRORになることを確認する
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunNotExists) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_BINARY_DIR "/executor/not_exists", output_file_path.native()}, 1000,
      10000, false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_ERROR);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, 0);
}

// 実行権限がついていないファイルの実行がFAULT_ERRORになることを確認する
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunPermissionDenied) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_DICTIONARY_DIR "/test.dict", output_file_path.native()}, 1000,
      10000, false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_ERROR);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, 0);
}

// 実行権限が付いているが実際には実行できないファイルの実行がFAULT_ERRORになることを確認する
BOOST_AUTO_TEST_CASE(NativeLinuxExecutorNativeRunNotExecutable) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // Setup output file path
  auto output_file_path = output_dir / "result";
  std::cout << "[*] output_file_path = " + output_file_path.native()
            << std::endl;

  // Create executor instance
  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  auto path_to_write_seed = output_dir / "cur_input";
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_SOURCE_DIR "/executor/not_executable", output_file_path.native()},
      1000, 10000, false, path_to_write_seed, PAGE_SIZE, PAGE_SIZE);
  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input;
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_ERROR);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().signal, 0);
}
