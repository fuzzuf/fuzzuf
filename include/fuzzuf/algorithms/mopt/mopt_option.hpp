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

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_OPTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_OPTION_HPP

#include "fuzzuf/algorithms/afl/afl_option.hpp"

namespace fuzzuf::algorithm::mopt::option {

struct MOptTag {};

template <class Tag>
constexpr u32 GetSpliceCyclesUp(void) {
  return 25;
}

template <class Tag>
constexpr u32 GetSpliceCyclesLow(void) {
  return 5;
}

template <class Tag>
constexpr u32 GetPeriodPilot(void) {
  return 50000;
}

template <class Tag>
constexpr u32 GetPeriodCore(void) {
  return 500000;
}

template <class Tag>
constexpr double GetLimitTimeBound(void) {
  return 1.1;
}

}  // namespace fuzzuf::algorithm::mopt::option

#endif
