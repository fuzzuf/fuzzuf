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
/**
 * @file executor.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/executor/executor.hpp"

#include <cassert>
#include <cstddef>
#include <memory>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::executor {

Executor::Executor(const std::vector<std::string> &argv, u32 exec_timelimit_ms,
                   u64 exec_memlimit, const std::string path_str_to_write_input)
    : argv(argv),
      exec_timelimit_ms(exec_timelimit_ms),
      exec_memlimit(exec_memlimit),
      // Although cargv refers path_str_to_write_input.c_str(),
      // since the lifetime of fs::path::c_str is non deterministic, avoid using
      // it.
      path_str_to_write_input(path_str_to_write_input),
      child_pid(0),
      input_fd(-1),
      null_fd(-1),
      stdin_mode(false) {}

/**
 * Precondition:
 *  - A file can be created at path path_str_to_write_input.
 * Postcondition:
 *  - enable input_fd member. In othe word, open the file specified by
 * path_str_to_write_input, then assign the file descriptor to input_fd.
 *  - enable null_fd member. In other word, open "/dev/null", then assign the
 * file descriptor to null_fd.
 */
void Executor::OpenExecutorDependantFiles() {
  input_fd = fuzzuf::utils::OpenFile(path_str_to_write_input,
                                     O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  null_fd = fuzzuf::utils::OpenFile("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(input_fd > -1 && null_fd > -1);
}

/**
 * Precondition:
 *  - input_fd is a file descriptor that points a file of fuzz.
 * Postcondition:
 *  - Write out the data pointed by buf to the file pointed by input_fd.
 *  - The written out file only contains data pointed by buf.
 *  - The size of written out file is smaller or equal to the value specified by
 * len.
 *  - Seek "file position indicator" to head of the file for reading the file
 * from target process. Check if the current execution path brings anything new
 * to the table. Update virgin bits to reflect the finds. Returns 1 if the only
 * change is the hit-count for a particular tuple; 2 if there are new tuples
 * seen. Updates the map, so subsequent calls will always return 0.
 *
 * This function is called after every exec() on a fairly large buffer, so
 * it needs to be fast. We do this in 32-bit and 64-bit flavors.
 */
void Executor::WriteTestInputToFile(const u8 *buf, u32 len) {
  assert(input_fd > -1);

  fuzzuf::utils::SeekFile(input_fd, 0, SEEK_SET);
  fuzzuf::utils::WriteFile(input_fd, buf, len);
  if (fuzzuf::utils::TruncateFile(input_fd, len)) ERROR("ftruncate() failed");
  fuzzuf::utils::SeekFile(input_fd, 0, SEEK_SET);
}

/*
 * Postcondition:
 *  - When child_pid has valid value,
 *      - Kill the process specified by child_pid
 *      - Then, inactivate the value of child_pid (for fail-safe)
 *  Note that it doesn't call waitpid (It is expected to be called in different
 * location)
 */
void Executor::KillChildWithoutWait() {
  if (child_pid > 0) {
    kill(child_pid, SIGKILL);
    child_pid = -1;
  }
}

}  // namespace fuzzuf::executor
