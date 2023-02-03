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
#include "fuzzuf/feedback/persistent_memory_feedback.hpp"

#include <cstddef>
#include <unordered_map>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::feedback {

PersistentMemoryFeedback::PersistentMemoryFeedback() : mem(nullptr), len(0) {}

PersistentMemoryFeedback::PersistentMemoryFeedback(const u8* orig_mem, u32 len)
    : mem(std::make_unique<u8[]>(len)), len(len) {
  std::copy(orig_mem, orig_mem + len, mem.get());
}

PersistentMemoryFeedback::PersistentMemoryFeedback(
    PersistentMemoryFeedback&& orig)
    : mem(std::move(orig.mem)), len(orig.len), trace(std::move(orig.trace)) {
  // now orig.trace are "valid but unspecified state" so we can call clear just
  // in case
  orig.trace.clear();
  // for orig.mem, it is guaranteed it becomes nullptr
}

PersistentMemoryFeedback& PersistentMemoryFeedback::operator=(
    PersistentMemoryFeedback&& orig) {
  std::swap(mem, orig.mem);
  std::swap(trace, orig.trace);

  len = orig.len;
  orig.len = 0;

  orig.mem.reset();
  orig.trace.clear();

  return *this;
}

u32 PersistentMemoryFeedback::CalcCksum32() const {
  using fuzzuf::algorithm::afl::option::AFLTag;
  using fuzzuf::algorithm::afl::option::GetHashConst;
  return fuzzuf::utils::Hash32(mem.get(), len, GetHashConst<AFLTag>());
}

u32 PersistentMemoryFeedback::CountNonZeroBytes() const {
  return fuzzuf::utils::CountBytes(mem.get(), len);
}

// Return mem held by PersistentMemoryFeedback as unordered_map consists of
// non-zero elements It currently returns an empty trace just after an
// initialization if mem is nullptr (error might be better)
// TODO: change the type of the return values from map to py::array_t
std::unordered_map<int, u8> PersistentMemoryFeedback::GetTrace(void) {
  if (!trace.empty() || mem == nullptr) return trace;

  for (u32 i = 0; i < len; i++) {
    if (mem[i]) trace[i] = mem[i];
  }
  return trace;
}

}  // namespace fuzzuf::feedback
