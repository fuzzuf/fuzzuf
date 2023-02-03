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
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::feedback {

// Executorがファイル内にfeedbackを書き込んで返す場合に使うクラス
// このクラスのインスタンスが生きている間、インスタンスが参照しているファイルを管理しているExecutorは新しいPUTの実行ができない
// インスタンスを破棄したい場合は、FileFeedback::DiscardActiveを使うこと
class FileFeedback {
 public:
  // prohibit copy constructors,
  // because copying this class can easily and accidentally make executor locked
  // the "active" instance should be at most only one always
  FileFeedback(const FileFeedback&) = delete;
  FileFeedback& operator=(const FileFeedback&) = delete;

  // we have no choice but to define the constructor without arguments
  // because sometimes we need to retrieve new instances via arguments like
  // 'FileFeedback &new_feed'
  FileFeedback();

  FileFeedback(FileFeedback&&);
  FileFeedback& operator=(FileFeedback&&);

  // TODO: should we pass "raw file" which is already opened
  // instead of passing a path like this?
  FileFeedback(fs::path feed_path, std::shared_ptr<u8> executor_lock);

  // If you want to discard the active instance to start a new execution,
  // then use this like FileFeedback::DiscardActive(std::move(feed))
  static void DiscardActive(FileFeedback /* unused_arg */);

  fs::path feed_path;

 private:
  std::shared_ptr<u8> executor_lock;
};

}  // namespace fuzzuf::feedback
