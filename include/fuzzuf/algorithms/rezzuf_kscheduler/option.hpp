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

#ifndef FUZZUF_INCLUDE_ALGORITHM_REZZUF_KSCHEDULER_OPTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_REZZUF_KSCHEDULER_OPTION_HPP

#include "fuzzuf/algorithms/afl/afl_option.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {
struct RezzufKSchedulerState;
}

namespace fuzzuf::algorithm::afl::option {

struct RezzufKSchedulerTag {};

template <>
constexpr u32 GetHavocStackPow2<RezzufKSchedulerTag>(void) {
  return 6;
}

/* Baseline number of random tweaks during a single 'havoc' stage: */
template <>
constexpr u32 GetHavocCycles<rezzuf_kscheduler::RezzufKSchedulerState>(rezzuf_kscheduler::RezzufKSchedulerState&) {
  return 24u;
}

template <>
constexpr u32 GetHavocCyclesInit<rezzuf_kscheduler::RezzufKSchedulerState>(rezzuf_kscheduler::RezzufKSchedulerState&) {
  return 64u;
}

/* Maximum multiplier for the above (should be a power of two, beware
    of 32-bit int overflows): */
template <>
constexpr u32 GetHavocMaxMult<rezzuf_kscheduler::RezzufKSchedulerState>(rezzuf_kscheduler::RezzufKSchedulerState&) {
  return 160u;
}

/* Absolute minimum number of havoc cycles (after all adjustments): */
template <>
constexpr s32 GetHavocMin<rezzuf_kscheduler::RezzufKSchedulerState>(rezzuf_kscheduler::RezzufKSchedulerState&) {
  return 64;
}

/* Nominal per-splice havoc cycle length: */
template <>
constexpr u32 GetSpliceHavoc<rezzuf_kscheduler::RezzufKSchedulerState>(rezzuf_kscheduler::RezzufKSchedulerState&) {
  return 1;
}

template <>
constexpr u32 GetPlotUpdateSec<RezzufKSchedulerTag>(void) {
  return 5u;
}


template <>
constexpr bool EnableKScheduler<RezzufKSchedulerTag>(void) {
  return true;
}

template <>
constexpr bool EnableKSchedulerSortByEnergy<RezzufKSchedulerTag>(void) {
  return true;
}

template <>
struct perf_type<RezzufKSchedulerTag> {
  using type = double;
};

template <>
constexpr bool EnableVerboseDebugLog<RezzufKSchedulerTag>(void) {
  return false;
}

template <>
constexpr bool EnableSequentialID<RezzufKSchedulerTag>(void) {
  return true;
}



}  // namespace fuzzuf::algorithm::afl::option

#endif
