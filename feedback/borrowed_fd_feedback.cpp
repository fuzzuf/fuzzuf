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
#include "fuzzuf/feedback/borrowed_fd_feedback.hpp"

#include <cstddef>
#include <functional>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::feedback {

BorrowedFdFeedback::BorrowedFdFeedback() : fd(-1) {}

BorrowedFdFeedback::BorrowedFdFeedback(int fd,
                                       std::shared_ptr<u8> executor_lock)
    : fd(fd), executor_lock(executor_lock) {}

BorrowedFdFeedback::BorrowedFdFeedback(BorrowedFdFeedback&& orig)
    : fd(orig.fd), executor_lock(std::move(orig.executor_lock)) {}

BorrowedFdFeedback& BorrowedFdFeedback::operator=(BorrowedFdFeedback&& orig) {
  std::swap(fd, orig.fd);
  std::swap(executor_lock, orig.executor_lock);

  return *this;
}

void BorrowedFdFeedback::Read(void* buf, u32 len) {
  fuzzuf::utils::ReadFile(fd, buf, len);
}

u32 BorrowedFdFeedback::ReadTimed(void* buf, u32 len, u32 timeout_ms) {
  return fuzzuf::utils::ReadFileTimed(fd, buf, len, timeout_ms);
}

void BorrowedFdFeedback::Write(void* buf, u32 len) {
  fuzzuf::utils::WriteFile(fd, buf, len);
}

// This is static method
// the argument name is commented out to suppress unused-value-warning
void BorrowedFdFeedback::DiscardActive(
    BorrowedFdFeedback /* unused_and_discarded_arg */) {
  // Do nothing.
  // At the end of this function, the argument unused_and_discarded_arg will be
  // destructed This is what this function means
}

}  // namespace fuzzuf::feedback
