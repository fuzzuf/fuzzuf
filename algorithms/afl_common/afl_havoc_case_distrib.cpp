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

#include "fuzzuf/algorithms/afl/afl_havoc_case_distrib.hpp"

#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/optimizer/keys.hpp"
#include "fuzzuf/optimizer/store.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::afl {

AFLHavocCaseDistrib::AFLHavocCaseDistrib() {}

AFLHavocCaseDistrib::~AFLHavocCaseDistrib() {}

// In the following section, we define the probability distribution for the
// havoc mutation. The definition consists of the following two steps:
//   1. initialize the weights that represent
//      the probabilities of each case being selected in Havoc.
//   2. initialize discrete_distribution with the weights.
//
// The problem here is that the weights should be changed depending on whether
// AFL has extras and auto extras(constant strings included in the
// dictionaries). Therefore, we need to define 4 sets of weights, each of which
// represents the probabilities in the case where AFL has {some, no} extras and
// {some, no} auto extras.
//
// Also, right below, we use constexpr and static variables a lot.
// AFL doesn't modify the weights and distributions dynamically,
// so we don't want to initialize them more than once.
// This is why the following functions use constexpr and are a little bit hard
// to read.

u32 AFLHavocCaseDistrib::CalcValue() {
  const auto& extras = optimizer::Store::GetInstance()
                           .Get(optimizer::keys::Extras)
                           .value()
                           .get();
  const auto& a_extras = optimizer::Store::GetInstance()
                             .Get(optimizer::keys::AutoExtras)
                             .value()
                             .get();

  // Static part: the following part doesn't run after a fuzzing campaign
  // starts.

  using afl::util::AFLGetCaseWeights;
  constexpr std::array<double, mutator::NUM_CASE> weight_set[2][2] = {
      {AFLGetCaseWeights(false, false), AFLGetCaseWeights(false, true)},
      {AFLGetCaseWeights(true, false), AFLGetCaseWeights(true, true)}};

  using fuzzuf::utils::random::WalkerDiscreteDistribution;
  static WalkerDiscreteDistribution<u32> dists[2][2] = {
      {WalkerDiscreteDistribution<u32>(weight_set[0][0].cbegin(),
                                       weight_set[0][0].cend()),
       WalkerDiscreteDistribution<u32>(weight_set[0][1].cbegin(),
                                       weight_set[0][1].cend())},
      {WalkerDiscreteDistribution<u32>(weight_set[1][0].cbegin(),
                                       weight_set[1][0].cend()),
       WalkerDiscreteDistribution<u32>(weight_set[1][1].cbegin(),
                                       weight_set[1][1].cend())}};

  // Dynamic part: the following part runs during a fuzzing campaign

  bool has_extras = !extras.empty();
  bool has_aextras = !a_extras.empty();
  return static_cast<mutator::HavocCase>(dists[has_extras][has_aextras]());
}

}  // namespace fuzzuf::algorithm::afl
