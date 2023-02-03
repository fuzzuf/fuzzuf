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

#include <ostream>

#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::mutator {

// This enum represents each switch case in Mutator::Havoc
// Because these enum values are often converted to integers,
// we can't use enum class...
enum HavocCase : u32 {
  FLIP1,
  FLIP2,
  FLIP4,
  FLIP8,
  FLIP16,
  FLIP32,
  ADD8,
  ADD16_LE,
  ADD16_BE,
  ADD32_LE,
  ADD32_BE,
  SUB8,
  SUB16_LE,
  SUB16_BE,
  SUB32_LE,
  SUB32_BE,
  INT8,
  INT16_LE,
  INT16_BE,
  INT32_LE,
  INT32_BE,
  XOR,
  DELETE_BYTES,
  CLONE_BYTES,
  INSERT_SAME_BYTE,
  INSERT_EXTRA,
  INSERT_AEXTRA,
  OVERWRITE_WITH_CHUNK,
  OVERWRITE_WITH_SAME_BYTE,
  OVERWRITE_WITH_EXTRA,
  OVERWRITE_WITH_AEXTRA,
  SUBADD8,
  SUBADD16,
  SUBADD32,
  // SPLICE
  NUM_CASE  // this represents the number of members
};

// we need to give how to print these enum values, for tests using boost

}  // namespace fuzzuf::mutator
