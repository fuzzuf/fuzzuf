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
#include <unordered_map>

#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::feedback {

// InplaceMemoryFeedbackはライフタイムがExecutorに縛られているため、それを回避したい場合こちらを使う
// InplaceMemoryFeedback::ConvertToPersistentで変換可能
class PersistentMemoryFeedback {
 public:
  PersistentMemoryFeedback();

  // prohibit copies
  PersistentMemoryFeedback(const PersistentMemoryFeedback&) = delete;
  PersistentMemoryFeedback& operator=(const PersistentMemoryFeedback&) = delete;

  // allow moves
  PersistentMemoryFeedback(PersistentMemoryFeedback&&);
  PersistentMemoryFeedback& operator=(PersistentMemoryFeedback&&);

  explicit PersistentMemoryFeedback(const u8* mem, u32 len);

  u32 CalcCksum32() const;
  u32 CountNonZeroBytes() const;

  // 主にPythonFuzzer向けのメソッド。cppのTODO参照
  std::unordered_map<int, u8> GetTrace(void);

  std::unique_ptr<u8[]> mem;
  u32 len;

  // 主にPythonFuzzer向けの要素。cppのTODO参照
  std::unordered_map<int, u8> trace;
};

}  // namespace fuzzuf::feedback
