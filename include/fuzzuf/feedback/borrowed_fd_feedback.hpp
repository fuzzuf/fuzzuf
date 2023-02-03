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

#include <functional>
#include <memory>

#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::feedback {

// Executorが後のPUT実行でも再利用するようなfdを一時的にfeedbackとして返す場合に使うクラス
// このクラスのインスタンスが生きている間、インスタンスが参照しているfdを持っているExecutorは新しいPUTの実行ができない
// インスタンスを破棄したい場合は、BorrowedFdFeedback::DiscardActiveを使うこと
class BorrowedFdFeedback {
 public:
  // prohibit copy constructors,
  // because copying this class can easily and accidentally make executor locked
  // the "active" instance should be at most only one always
  BorrowedFdFeedback(const BorrowedFdFeedback &) = delete;
  BorrowedFdFeedback &operator=(const BorrowedFdFeedback &) = delete;

  // we have no choice but to define the constructor without arguments
  // because sometimes we need to retrieve new instances via arguments like
  // 'BorrowedFdFeedback &new_feed'
  BorrowedFdFeedback();

  BorrowedFdFeedback(BorrowedFdFeedback &&);
  BorrowedFdFeedback &operator=(BorrowedFdFeedback &&);

  BorrowedFdFeedback(int fd, std::shared_ptr<u8> executor_lock);

  void Read(void *buf, u32 len);
  u32 ReadTimed(void *buf, u32 len, u32 timeout_ms);
  void Write(void *buf, u32 len);

  // If you want to discard the active instance to start a new execution,
  // then use this like BorrowedFdFeedback::DiscardActive(std::move(feed))
  static void DiscardActive(BorrowedFdFeedback /* unused_arg */);

 private:
  int fd;
  std::shared_ptr<u8> executor_lock;
};

}  // namespace fuzzuf::feedback
