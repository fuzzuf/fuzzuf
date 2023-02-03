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
/**
 * @file which.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::utils {

auto which(const fs::path &name) -> fs::path {
  if (name.is_absolute()) {
    return name;
  }

  if (name.has_parent_path()) {
    return name;
  }

  {
    auto *iter = std::getenv("PATH");
    auto *const global_end = std::next(iter, std::strlen(iter));
    if (iter != global_end) {
      do {
        auto *const local_end = std::find(iter, global_end, ':');

        const auto deterministic = fs::path(iter, local_end) / name;
        if (fs::exists(deterministic) && !fs::is_directory(deterministic)) {
          return deterministic;
        }
        iter = std::find_if(local_end, global_end,
                            [](auto c) { return c != ':'; });
      } while (iter != global_end);
    }
  }

  const std::size_t default_path_size = confstr(_CS_PATH, nullptr, 0U);
  if (default_path_size != 0U) {
    std::vector<char> default_path(default_path_size + 1U);
    const std::size_t default_path_size_ =
        confstr(_CS_PATH, default_path.data(), default_path.size());
    assert(default_path_size == default_path_size_);

    auto iter = default_path.begin();
    const auto global_end = default_path.end();
    if (iter != global_end) {
      do {
        const auto local_end = std::find(iter, global_end, ':');

        auto deterministic = fs::path(iter, local_end) / name;
        if (fs::exists(deterministic) && !fs::is_directory(deterministic)) {
          return deterministic;
        }
        iter = std::find_if(local_end, global_end,
                            [](auto c) { return c != ':'; });
      } while (iter != global_end);
    }
  }
  return name;
}

}  // namespace fuzzuf::utils
