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
#include "fuzzuf/feedback/exit_status_feedback.hpp"

#include <cstddef>
#include <unordered_map>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::feedback {

ExitStatusFeedback::ExitStatusFeedback() {}

ExitStatusFeedback::ExitStatusFeedback(PUTExitReasonType exit_reason, u8 signal)
    : exit_reason(exit_reason), signal(signal) {}

ExitStatusFeedback::ExitStatusFeedback(const ExitStatusFeedback& orig)
    : exit_reason(orig.exit_reason), signal(orig.signal) {}

ExitStatusFeedback& ExitStatusFeedback::operator=(
    const ExitStatusFeedback& orig) {
  exit_reason = orig.exit_reason;
  signal = orig.signal;

  return *this;
}

}  // namespace fuzzuf::feedback
