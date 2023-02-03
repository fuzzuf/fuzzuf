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

#include "fuzzuf/algorithms/afl/afl_option.hpp"

namespace fuzzuf::algorithm::aflfast::option {

enum Schedule {
  /* 00 */ FAST,    /* Exponential schedule             */
  /* 01 */ COE,     /* Cut-Off Exponential schedule     */
  /* 02 */ EXPLORE, /* Exploration-based constant sch.  */
  /* 03 */ LIN,     /* Linear schedule                  */
  /* 04 */ QUAD,    /* Quadratic schedule               */
  /* 05 */ EXPLOIT  /* AFL's exploitation-based const.  */
};

struct AFLFastTag {};

/* Power Schedule Divisor */
template <class State>
constexpr u32 GetPowerBeta(State&) {
  return 1;
}

template <class State>
constexpr u32 GetMaxFactor(State& state) {
  return GetPowerBeta(state) * 32;
}

}  // namespace fuzzuf::algorithm::aflfast::option
