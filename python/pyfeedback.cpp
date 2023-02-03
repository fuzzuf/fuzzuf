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
#include "fuzzuf/python/pyfeedback.hpp"

namespace fuzzuf::bindings::python {

PyFeedback::PyFeedback(
    const std::optional<std::unordered_map<int, u8>> bb_trace,
    const std::optional<std::unordered_map<int, u8>> afl_trace)
    : bb_trace(bb_trace), afl_trace(afl_trace) {}

std::optional<std::unordered_map<int, u8>> PyFeedback::GetBBTrace(void) {
  return bb_trace;
}

std::optional<std::unordered_map<int, u8>> PyFeedback::GetAFLTrace(void) {
  return afl_trace;
}

}  // namespace fuzzuf::bindings::python
