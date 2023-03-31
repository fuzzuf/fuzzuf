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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_AFLPLUSPLUS_AFLPLUSPLUS_UTIL_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_AFLPLUSPLUS_AFLPLUSPLUS_UTIL_HPP

#include <algorithm>
#include <numeric>
#include <vector>

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::aflplusplus::util {

// A small constant used instead of 0
// to avoid buggy situations like "1.0/0.0"
const double epsilon = 1e-8;

/*
 * These utility functions are supposed to be
 * used with *AFLplusplusState-like* State instances.
 */

template <class State>
double ComputeWeight(const State &state,
                     const typename State::OwnTestcase &testcase,
                     const double &avg_exec_us, const double &avg_bitmap_size,
                     const double &avg_top_size) {
  double weight = 1.0;

  u32 hits = state.n_fuzz[testcase.n_fuzz_entry];
  if (likely(hits)) {
    weight *= std::log10(hits) + 1;
  }

  weight *= ((avg_exec_us + epsilon) / (testcase.exec_us + epsilon));
  weight *= (std::log(testcase.bitmap_size + 1) / (avg_bitmap_size + epsilon));
  weight *= (1 + (testcase.tc_ref / (avg_top_size + epsilon)));
  if (unlikely(testcase.favored)) {
    weight *= 5;
  }
  if (unlikely(!testcase.WasFuzzed())) {
    weight *= 2;
  }

  return weight;
}

template <class State>
void ComputeWeightVector(State &state, std::vector<double> &vw) {
  u32 queued_items = state.case_queue.size();

  double avg_exec_us = 0.0, avg_bitmap_size = 0.0, avg_top_size = 0.0;
  for (auto &tc : state.case_queue) {
    avg_exec_us += tc->exec_us;
    avg_bitmap_size += std::log(tc->bitmap_size + 1);
    avg_top_size += tc->tc_ref;
  }
  avg_exec_us /= queued_items;
  avg_bitmap_size /= queued_items;
  avg_top_size /= queued_items;

  std::transform(state.case_queue.begin(), state.case_queue.end(),
                 std::back_inserter(vw), [&](auto &tc) {
                   return ComputeWeight(state, *tc, avg_exec_us,
                                        avg_bitmap_size, avg_top_size);
                 });
}

/* create the alias table that allows weighted random selection - expensive */
template <class State>
void CreateAliasTable(State &state) {
  std::vector<double> vw;
  ComputeWeightVector(state, vw);
  for (double &w : vw) {
    if (-epsilon <= w && w < 0) w = 0;
  }
  using utils::random::WalkerDiscreteDistribution;
  state.alias_probability.reset(new WalkerDiscreteDistribution<u32>(vw));
}

}  // namespace fuzzuf::algorithm::aflplusplus::util

#endif
