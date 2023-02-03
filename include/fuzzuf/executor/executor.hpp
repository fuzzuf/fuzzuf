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
#pragma once

#include <memory>

#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::executor {

struct ChildState {
  int exec_result;
  int exec_errno;
};

constexpr std::size_t output_block_size = 512u;

// A base class that abstracts any kinds of execution environments and fuzz
// executions. Inherit this class if you want to derive `FooBarExecutor` for a
// new execution environment, FooBar. The following notes are applied to this
// class and its derivatives.
//
// Responsibility:
//
//  - Initialize all member variables of the class itself and its derivatives
//  - All member variables must have valid values assigned after initialization
class Executor {
 public:
  // Members holding settings handed over a constructor
  const std::vector<std::string> argv;
  u32 exec_timelimit_ms;
  u64 exec_memlimit;

  std::vector<const char *>
      cargv;  // argv converted to char*. Do not reference after the lifetime of
              // argv ends as an address pointed by char* is obtained by c_str()

  // A filepath given to the PUT which reads an input over the file (note that
  // Executor creates a file to the path)
  const std::string path_str_to_write_input;

  int child_pid;

  int input_fd;  // Used for stdin mode in Executor::Run()
  int null_fd;
  bool stdin_mode;  // FIXME: Maybe use struct NativeLinuxExecutorArgs{cargv,
                    // stdin_mode} and make is const

  Executor(const std::vector<std::string> &argv, u32 exec_timelimit_ms,
           u64 exec_memlimit, const std::string path_str_to_write_input);
  virtual ~Executor(){};

  Executor(const Executor &) = delete;
  Executor(Executor &&) = delete;
  Executor &operator=(const Executor &) = delete;
  Executor &operator=(Executor &&) = delete;
  Executor() = delete;

  // Define the common interface used in each execution environment
  // Read an input and actually execute the PUT
  virtual void Run(const u8 *buf, u32 len, u32 timeout_ms = 0) = 0;

  void KillChildWithoutWait();

  // Called when fuzzuf needs to be stopped earlier, such as when SIGTERM is
  // triggered
  virtual void ReceiveStopSignal(void) = 0;

  void OpenExecutorDependantFiles();
  void WriteTestInputToFile(const u8 *buf, u32 len);

 protected:
  std::shared_ptr<u8> lock;
};

}  // namespace fuzzuf::executor
