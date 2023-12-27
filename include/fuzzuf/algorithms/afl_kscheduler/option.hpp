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
#ifndef FUZZUF_INCLUDE_ALGORITHM_AFL_KSCHEDULER_OPTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_AFL_KSCHEDULER_OPTION_HPP

#include "fuzzuf/algorithms/afl/afl_option.hpp"

namespace fuzzuf::algorithm::afl_kscheduler {
struct AFLKSchedulerState;
}

namespace fuzzuf::algorithm::afl::option {

struct AFLKSchedulerTag {};

/* Baseline number of random tweaks during a single 'havoc' stage: */
template <>
constexpr u32 GetHavocCycles<afl_kscheduler::AFLKSchedulerState>(afl_kscheduler::AFLKSchedulerState&) {
  return 24u;
}

template <>
constexpr u32 GetHavocCyclesInit<afl_kscheduler::AFLKSchedulerState>(afl_kscheduler::AFLKSchedulerState&) {
  return 64u;
}

/* Maximum multiplier for the above (should be a power of two, beware
    of 32-bit int overflows): */
template <>
constexpr u32 GetHavocMaxMult<afl_kscheduler::AFLKSchedulerState>(afl_kscheduler::AFLKSchedulerState&) {
  return 160u;
}

/* Absolute minimum number of havoc cycles (after all adjustments): */
template <>
constexpr s32 GetHavocMin<afl_kscheduler::AFLKSchedulerState>(afl_kscheduler::AFLKSchedulerState&) {
  return 64;
}

/* Nominal per-splice havoc cycle length: */
template <>
constexpr u32 GetSpliceHavoc<afl_kscheduler::AFLKSchedulerState>(afl_kscheduler::AFLKSchedulerState&) {
  return 1;
}

template <>
constexpr u32 GetPlotUpdateSec<AFLKSchedulerTag>(void) {
  return 5u;
}


template <>
constexpr bool EnableKScheduler<AFLKSchedulerTag>(void) {
  return true;
}

template <>
constexpr bool EnableKSchedulerSortByEnergy<AFLKSchedulerTag>(void) {
  return true;
}

template <>
struct perf_type<AFLKSchedulerTag> {
  using type = double;
};

template <>
constexpr bool EnableVerboseDebugLog<AFLKSchedulerTag>(void) {
  return false;
}

template <>
constexpr bool EnableSequentialID<AFLKSchedulerTag>(void) {
  return true;
}

}  // namespace fuzzuf::algorithm::afl::option

#endif

