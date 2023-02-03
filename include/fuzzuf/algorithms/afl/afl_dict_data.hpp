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

#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::afl::dictionary {

struct AFLDictData {
  using word_t = std::vector<u8>;

  AFLDictData() {}

  AFLDictData(const word_t &v) : data(v) {}

  AFLDictData(const word_t &v, u32 h) : data(v), hit_cnt(h) {}

  const std::vector<u8> get() const { return data; }

  std::vector<u8> data;
  u32 hit_cnt = 0u;
};

void load(const std::string &filename_, std::vector<AFLDictData> &dest,
          bool strict, const std::function<void(std::string &&)> &eout);

void SortDictByLength(std::vector<AFLDictData> &dict);

}  // namespace fuzzuf::algorithm::afl::dictionary
