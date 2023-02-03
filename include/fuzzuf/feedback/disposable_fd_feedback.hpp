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

// Executorが今回のPUT実行のために生成したfdをfeedbackとして返す場合に使うクラス
// つまり、fdは再利用されることがなく、feedbackの受け取り手が好きに使っていい（closeしてもよい）場合を想定
class DisposableFdFeedback {
 public:
  DisposableFdFeedback();

  DisposableFdFeedback(const DisposableFdFeedback &);
  DisposableFdFeedback &operator=(const DisposableFdFeedback &);

  DisposableFdFeedback(int fd);

  void Read(void *buf, u32 len);
  u32 ReadTimed(void *buf, u32 len, u32 timeout_ms);
  void Write(void *buf, u32 len);

  // TODO:
  // いくら捨てて良いfdでも好き勝手にコピーされcloseされないのはまずいかも？
  // BorrowedFdFeedbackと同様にコピー不可にしつつ、destructorでclose(fd)してもいいかも
  int fd;
};

}  // namespace fuzzuf::feedback
