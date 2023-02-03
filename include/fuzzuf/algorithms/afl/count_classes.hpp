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

#include <array>

#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::afl {

// To use a constexpr function as the initializer of count_class_lookup*,
// we need to put these 2 arrays into one struct
struct CountClasses {
  std::array<u8, 256> lookup8;
  std::array<u16, 65536> lookup16;
};

}  // namespace fuzzuf::algorithm::afl
