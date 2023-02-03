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
#include "fuzzuf/feedback/disposable_fd_feedback.hpp"

#include <cstddef>
#include <functional>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::feedback {

DisposableFdFeedback::DisposableFdFeedback() : fd(-1) {}

DisposableFdFeedback::DisposableFdFeedback(int fd) : fd(fd) {}

DisposableFdFeedback::DisposableFdFeedback(const DisposableFdFeedback& orig)
    : fd(orig.fd) {}

DisposableFdFeedback& DisposableFdFeedback::operator=(
    const DisposableFdFeedback& orig) {
  fd = orig.fd;

  return *this;
}

void DisposableFdFeedback::Read(void* buf, u32 len) {
  fuzzuf::utils::ReadFile(fd, buf, len);
}

u32 DisposableFdFeedback::ReadTimed(void* buf, u32 len, u32 timeout_ms) {
  return fuzzuf::utils::ReadFileTimed(fd, buf, len, timeout_ms);
}

void DisposableFdFeedback::Write(void* buf, u32 len) {
  fuzzuf::utils::WriteFile(fd, buf, len);
}

}  // namespace fuzzuf::feedback
