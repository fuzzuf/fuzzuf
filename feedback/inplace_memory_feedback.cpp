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
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"

#include <cstddef>
#include <functional>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::feedback {

InplaceMemoryFeedback::InplaceMemoryFeedback() : mem(nullptr), len(0) {}

InplaceMemoryFeedback::InplaceMemoryFeedback(u8* _mem, u32 _len,
                                             std::shared_ptr<u8> _executor_lock)
    : mem(_mem), len(_len), executor_lock(_executor_lock) {}

InplaceMemoryFeedback::InplaceMemoryFeedback(InplaceMemoryFeedback&& orig)
    : mem(orig.mem),
      len(orig.len),
      executor_lock(std::move(orig.executor_lock)) {
  orig.mem = nullptr;
}

InplaceMemoryFeedback& InplaceMemoryFeedback::operator=(
    InplaceMemoryFeedback&& orig) {
  mem = orig.mem;
  orig.mem = nullptr;

  len = orig.len;

  std::swap(executor_lock, orig.executor_lock);

  return *this;
}

// FIXME: check reference count in all the functions below in debug mode

PersistentMemoryFeedback InplaceMemoryFeedback::ConvertToPersistent() const {
  if (mem == nullptr) return PersistentMemoryFeedback();
  return PersistentMemoryFeedback(mem, len);
}

u32 InplaceMemoryFeedback::CalcCksum32() const {
  using fuzzuf::algorithm::afl::option::AFLTag;
  using fuzzuf::algorithm::afl::option::GetHashConst;
  return fuzzuf::utils::Hash32(mem, len, GetHashConst<AFLTag>());
}

u32 InplaceMemoryFeedback::CountNonZeroBytes() const {
  return fuzzuf::utils::CountBytes(mem, len);
}

void InplaceMemoryFeedback::ShowMemoryToFunc(
    const std::function<void(const u8*, u32)>& func) const {
  func(mem, len);
}

void InplaceMemoryFeedback::ModifyMemoryWithFunc(
    const std::function<void(u8*, u32)>& func) {
  func(mem, len);
}

// This is static method
// the argument name is commented out to suppress unused-value-warning
void InplaceMemoryFeedback::DiscardActive(
    InplaceMemoryFeedback /* unused_and_discarded_arg */) {
  // Do nothing.
  // At the end of this function, the argument unused_and_discarded_arg will be
  // destructed This is what this function means
}

}  // namespace fuzzuf::feedback
