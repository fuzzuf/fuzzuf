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
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/algorithms/afl/count_classes.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_option.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/mutator/mutator.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::aflplusplus::havoc {

/**
 * @fn AFLplusplusGetCaseWeights
 * Returns the weights that represent the probabilities of each case being
 * selected in Havoc.
 * @note Ridiculously, we need a constexpr function just in order to initialize
 * static arrays with enum constants(i.e. to use a kind of designated
 * initialization)
 */
static constexpr std::array<double, AFLPLUSPLUS_NUM_CASE>
AFLplusplusGetCaseWeights(bool has_extras, bool has_a_extras) {
  std::array<double, AFLPLUSPLUS_NUM_CASE> weights{};

  weights[mutator::FLIP1] = 4.0;                     // case 0 ... 3
  weights[mutator::INT8] = 4.0;                      // case 4 ... 7
  weights[mutator::INT16_LE] = 2.0;                  // case 8 ... 9
  weights[mutator::INT16_BE] = 2.0;                  // case 10 ... 11
  weights[mutator::INT32_LE] = 2.0;                  // case 12 ... 13
  weights[mutator::INT32_BE] = 2.0;                  // case 14 ... 15
  weights[mutator::SUB8] = 4.0;                      // case 16 ... 19
  weights[mutator::ADD8] = 4.0;                      // case 20 ... 23
  weights[mutator::SUB16_LE] = 2.0;                  // case 24 ... 25
  weights[mutator::SUB16_BE] = 2.0;                  // case 26 ... 27
  weights[mutator::ADD16_LE] = 2.0;                  // case 28 ... 29
  weights[mutator::ADD16_BE] = 2.0;                  // case 30 ... 31
  weights[mutator::SUB32_LE] = 2.0;                  // case 32 ... 33
  weights[mutator::SUB32_BE] = 2.0;                  // case 34 ... 35
  weights[mutator::ADD32_LE] = 2.0;                  // case 36 ... 37
  weights[mutator::ADD32_BE] = 2.0;                  // case 38 ... 39
  weights[mutator::XOR] = 4.0;                       // case 40 ... 43
  weights[mutator::CLONE_BYTES] = 3.0;               // case 44 ... 46
  weights[mutator::INSERT_SAME_BYTE] = 1.0;          // case 47
  weights[mutator::OVERWRITE_WITH_CHUNK] = 3.0;      // case 48 ... 50
  weights[mutator::OVERWRITE_WITH_SAME_BYTE] = 1.0;  // case 51
  weights[AFLPLUSPLUS_ADDBYTE] = 1.0;                // case 52
  weights[AFLPLUSPLUS_SUBBYTE] = 1.0;                // case 53
  weights[mutator::FLIP8] = 1.0;                     // case 54
  weights[AFLPLUSPLUS_SWITCH_BYTES] = 2.0;           // case 55 ... 56
  weights[mutator::DELETE_BYTES] = 8.0;              // case 57 ... 64

  // FIXME: the weights of the following two cases increase depending
  // on the progress of fuzzing campaign. It should be reflected.
  weights[AFLPLUSPLUS_SPLICE_OVERWRITE] = 2.0;  // default case #1
  weights[AFLPLUSPLUS_SPLICE_INSERT] = 2.0;     // default case #2

  if (has_extras && has_a_extras) {
    weights[mutator::INSERT_EXTRA] = 1.0;
    weights[mutator::OVERWRITE_WITH_EXTRA] = 1.0;
    weights[mutator::INSERT_AEXTRA] = 1.0;
    weights[mutator::OVERWRITE_WITH_AEXTRA] = 1.0;
  } else if (has_extras) {
    weights[mutator::INSERT_EXTRA] = 2.0;
    weights[mutator::OVERWRITE_WITH_EXTRA] = 2.0;
  } else if (has_a_extras) {
    weights[mutator::INSERT_AEXTRA] = 2.0;
    weights[mutator::OVERWRITE_WITH_AEXTRA] = 2.0;
  }

  return weights;
}

AFLplusplusHavocCaseDistrib::AFLplusplusHavocCaseDistrib() {}
AFLplusplusHavocCaseDistrib::~AFLplusplusHavocCaseDistrib() {}
u32 AFLplusplusHavocCaseDistrib::CalcValue() {
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

  constexpr std::array<double, AFLPLUSPLUS_NUM_CASE> weight_set[2][2] = {
      {AFLplusplusGetCaseWeights(false, false),
       AFLplusplusGetCaseWeights(false, true)},
      {AFLplusplusGetCaseWeights(true, false),
       AFLplusplusGetCaseWeights(true, true)}};

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
  return static_cast<u32>(dists[has_extras][has_aextras]());
}

// Temporarily copy-and-paste ChooseBlockLen() function, rather than modifying
// all function prototypes of CustomCases. Looking for a better way to achieve
// this...
u32 ChooseBlockLen(u32 limit) {
  using Tag = aflplusplus::option::AFLplusplusTag;
  u32 min_value, max_value;
  u32 rlim = 3ULL;

  // just an alias of afl::util::UR
  auto UR = [](u32 limit) { return afl::util::UR(limit, -1); };

  switch (UR(rlim)) {
    case 0:
      min_value = 1;
      max_value = afl::option::GetHavocBlkSmall<Tag>();
      break;

    case 1:
      min_value = afl::option::GetHavocBlkSmall<Tag>();
      max_value = afl::option::GetHavocBlkMedium<Tag>();
      break;
    default:
      if (UR(10)) {
        min_value = afl::option::GetHavocBlkMedium<Tag>();
        max_value = afl::option::GetHavocBlkLarge<Tag>();
      } else {
        min_value = afl::option::GetHavocBlkLarge<Tag>();
        max_value = afl::option::GetHavocBlkXl<Tag>();
      }
  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(std::min(max_value, limit) - min_value + 1);
}

}  // namespace fuzzuf::algorithm::aflplusplus::havoc
