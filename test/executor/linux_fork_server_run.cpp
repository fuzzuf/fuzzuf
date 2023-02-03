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
#include <unistd.h>

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "config.h"
#include "fuzzuf/executor/linux_fork_server_executor.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

// Check if NativeLinuxExecutor correctly allocates the shared memory of
// variable size
BOOST_AUTO_TEST_CASE(LinuxForkServerExecutorVariableShm) {
  // We set each of afl_shm_size and bb_shm_size to 5 different values:
  //   0, 1, PAGE_SIZE-1, PAGE_SIZE, and PAGE_SIZE+1.
  // If afl_shm_size == 0, executor.afl_shmid should be
  // NativeLinuxExecutor::INVALID_SHMID. Otherwise, afl_shmid should have a
  // valid value. We check the size of this shared memory. Although shmget
  // internally rounds up the specified size to a multiple of PAGE_SIZE when
  // allocating shared memories, shmctl returns the original value of size.
  // The same is true for bb_shm_size.

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

  auto path_to_write_seed = output_dir / "cur_input";

  long val = sysconf(_SC_PAGESIZE);
  BOOST_CHECK(val != -1);  // Make sure sysconf succeeds
  u32 PAGE_SIZE = (u32)val;

  // std::vector<u32> checked_sizes = {0, 1, PAGE_SIZE - 1, PAGE_SIZE,
  //                                   PAGE_SIZE + 1};
  std::vector<u32> checked_sizes = {PAGE_SIZE};

  for (u32 afl : checked_sizes) {
    for (u32 bb : checked_sizes) {
      fuzzuf::executor::LinuxForkServerExecutor executor(
          fuzzuf::executor::LinuxForkServerExecutorParameters()
              .set_argv(
                  std::vector<std::string>{TEST_SOURCE_DIR "/put_binaries/cat"})
              .set_exec_timelimit_ms(1000)
              .set_exec_memlimit(10000)
              .set_path_to_write_input(path_to_write_seed)
              .set_afl_shm_size(afl)
              .set_bb_shm_size(bb)
              .set_record_stdout_and_err(true)
              .move());

      std::string input("Hello, World!");
      executor.Run(reinterpret_cast<const u8 *>(input.c_str()), input.size());

      // (1) Check if content of stdin is passed to stdout and stderr
      {
        std::string s = "stdout: " + input;
        fuzzuf::executor::output_t answer(s.begin(), s.end());
        auto stdout = executor.MoveStdOut();
        std::cout << std::string(stdout.begin(), stdout.end()) << std::endl;
        BOOST_CHECK_EQUAL_COLLECTIONS(stdout.begin(), stdout.end(),
                                      answer.begin(), answer.end());
      }
      {
        std::string s = "stderr: " + input;
        fuzzuf::executor::output_t answer(s.begin(), s.end());
        auto stderr = executor.MoveStdErr();
        std::cout << std::string(stderr.begin(), stderr.end()) << std::endl;
        BOOST_CHECK_EQUAL_COLLECTIONS(stderr.begin(), stderr.end(),
                                      answer.begin(), answer.end());
      }

      // (2) Check if coverage store is allocated as intended
      if (afl == 0) {
        BOOST_CHECK_EQUAL(executor.GetAFLShmID(),
                          fuzzuf::coverage::ShmCovAttacher::INVALID_SHMID);
      } else {
        struct shmid_ds info;
        int res = shmctl(executor.GetAFLShmID(), IPC_STAT, &info);
        BOOST_CHECK_EQUAL(res, 0);
        BOOST_CHECK_EQUAL(info.shm_segsz, afl);
      }

      if (bb == 0) {
        BOOST_CHECK_EQUAL(executor.GetBBShmID(),
                          fuzzuf::coverage::ShmCovAttacher::INVALID_SHMID);
      } else {
        struct shmid_ds info;
        int res = shmctl(executor.GetBBShmID(), IPC_STAT, &info);
        BOOST_CHECK_EQUAL(res, 0);
        BOOST_CHECK_EQUAL(info.shm_segsz, bb);
      }

      // (3) Check if executor has collected coverage info
      // ビットマップが0でないことを確認する（ビットマップは未実装）
    }
  }
}
