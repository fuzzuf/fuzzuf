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
#include "fuzzuf/feedback/file_feedback.hpp"

#include <cstddef>
#include <functional>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::feedback {

FileFeedback::FileFeedback() {}

FileFeedback::FileFeedback(fs::path feed_path,
                           std::shared_ptr<u8> executor_lock)
    : feed_path(feed_path), executor_lock(executor_lock) {}

FileFeedback::FileFeedback(FileFeedback&& orig)
    : feed_path(orig.feed_path), executor_lock(std::move(orig.executor_lock)) {}

FileFeedback& FileFeedback::operator=(FileFeedback&& orig) {
  std::swap(feed_path, orig.feed_path);
  std::swap(executor_lock, orig.executor_lock);

  return *this;
}

// This is static method
// the argument name is commented out to suppress unused-value-warning
void FileFeedback::DiscardActive(FileFeedback /* unused_and_discarded_arg */) {
  // Do nothing.
  // At the end of this function, the argument unused_and_discarded_arg will be
  // destructed This is what this function means
}

}  // namespace fuzzuf::feedback
