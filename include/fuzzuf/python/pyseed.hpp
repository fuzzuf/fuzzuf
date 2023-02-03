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

#include <optional>
#include <unordered_map>
#include <vector>

#include "fuzzuf/python/pyfeedback.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::bindings::python {

class PySeed {
 public:
  PySeed(const u64 id, const std::vector<u8> buf,
         const std::optional<std::unordered_map<int, u8>> bb_trace,
         const std::optional<std::unordered_map<int, u8>> afl_trace);
  PySeed(const PySeed&) = delete;
  PySeed(PySeed&&) = default;
  PySeed& operator=(const PySeed&) = delete;
  PySeed& operator=(PySeed&&) = default;

  std::vector<u8> GetBuf(void) const;
  PyFeedback GetFeedback(void) const;
  u64 GetID(void) const;

 private:
  u64 id;
  std::vector<u8> buf;
  PyFeedback pyfeedback;
};

}  // namespace fuzzuf::bindings::python
