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
/**
 * @file update_feature_frequency.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_UPDATE_FEATURE_FREQUENCY_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_UPDATE_FEATURE_FREQUENCY_HPP
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/algorithms/libfuzzer/utils.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::feature {

/**
 * Increment counter at index-th element of global_feature_freqs
 * The counter value saturates
 * Since n-th element of global_feature_freqs indicates detection count of
 * feature ID n, index should be a valid feature ID.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L437
 *
 * @tparam State LibFuzzer state object type
 * @tparam InputInfo Type to provide execution result
 * @param state LibFuzzer state object
 * @param exec_result Execution result that was produced by the executor
 * @param index Index of value to increment
 */
template <typename State, typename InputInfo>
auto UpdateFeatureFrequency(State &state, InputInfo &exec_result,
                            std::size_t index)
    -> std::enable_if_t<is_state_v<State> && is_input_info_v<InputInfo>> {
  const std::uint32_t index32 =
      index % utils::range::rangeSize(state.global_feature_freqs);

  // Saturated increment.
  if (state.global_feature_freqs[index32] == 0xFFFF) return;
  std::uint16_t freq = state.global_feature_freqs[index32]++;

  // Skip if abundant.
  if (freq > state.freq_of_most_abundant_rare_feature ||
      std::find(state.rare_features.begin(), state.rare_features.end(),
                index32) == state.rare_features.end())
    return;

  if (freq == state.freq_of_most_abundant_rare_feature)
    ++state.freq_of_most_abundant_rare_feature;

  exec_result.updateFeatureFrequency(index);
}

}  // namespace fuzzuf::algorithm::libfuzzer::feature

#endif
