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
#define BOOST_TEST_MODULE executor.ijon
#define BOOST_TEST_DYN_LINK

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/linux_fork_server_executor.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/which.hpp"

// Check if IJON specific values are stored in shared memory
BOOST_AUTO_TEST_CASE(IJONExecute) {
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

  auto path_to_write_seed = output_dir / "cur_input";
  auto params = fuzzuf::executor::LinuxForkServerExecutorParameters()
                    .set_argv(std::vector<std::string>{
                        TEST_BINARY_DIR "/put/ijon/ijon-test_put1"})
                    .set_exec_timelimit_ms(1000)
                    .set_exec_memlimit(10000)
                    .set_path_to_write_input(path_to_write_seed)
                    .set_afl_shm_size(65536u)
                    .set_ijon_counter_shm_size(65536u)
                    .set_ijon_max_shm_size(65536u)
                    .set_record_stdout_and_err(false);
  const auto ijon_counter_offset = params.GetIjonCounterOffset();
  const auto ijon_max_offset = params.GetIjonMaxOffset();
  fuzzuf::executor::LinuxForkServerExecutor executor(params.move());

  BOOST_CHECK_EQUAL(executor.stdin_mode, true);

  // Invoke NativeLinuxExecutor::Run()
  std::string input("hogefuga");
  executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());

  // Check normality
  // (1) 正常実行されたこと → feedbackのexit_reason が
  // PUTExitReasonType::FAULT_NONE であることを確認する
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    fuzzuf::feedback::PUTExitReasonType::FAULT_NONE);

  executor.GetAFLFeedback().ShowMemoryToFunc([ijon_counter_offset,
                                              ijon_max_offset](const u8 *head,
                                                               u32 size) {
    // Retrived range has enough size
    BOOST_CHECK_GE(size, ijon_max_offset + 65536u);
    // At least one IJON counter is incremented
    BOOST_CHECK_EQUAL(std::size_t(std::count(
                          std::next(head, ijon_counter_offset),
                          std::next(head, ijon_counter_offset + 65536u), 0)),
                      65536u - 2u);
    // At least one IJON_MAX value is recorded
    BOOST_CHECK_EQUAL(
        std::size_t(std::count(std::next(head, ijon_max_offset),
                               std::next(head, ijon_max_offset + 65536u), 0)),
        65536u - 8u);
  });
}
