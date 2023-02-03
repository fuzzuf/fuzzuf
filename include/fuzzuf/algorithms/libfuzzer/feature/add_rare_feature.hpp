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
 * @file add_rare_feature.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_ADD_RARE_FEATURE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_ADD_RARE_FEATURE_HPP
#include <array>
#include <cstdint>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/algorithms/libfuzzer/utils.hpp"
#include "fuzzuf/utils/for_each_multi_index_values.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::algorithm::libfuzzer::feature {

/**
 * Append new feature to notable features.
 * If notable features exceeded max size, most common feature in notable
 * features is dropped.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L357
 *
 * @tparam State LibFuzzer state object type
 * @tparam Corpus FullCorpus type to add new execution result
 * @param state LibFuzzer state object
 * @param corpus FullCorpus. If a feature was dropped from notable features, it
 * is also removed from the partial corpus in the corpus.
 * @param index New feature
 */
template <typename State, typename Corpus>
auto AddRareFeature(State &state, Corpus &corpus, std::uint32_t index)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus>> {
  // Maintain *at least* TopXRarestFeatures many rare features
  // and all features with a frequency below ConsideredRare.
  // Remove all other features.
  while (state.rare_features.size() >
             state.create_info.config.entropic.number_of_rarest_features &&
         state.freq_of_most_abundant_rare_feature >
             state.create_info.config.entropic.feature_frequency_threshold) {
    // Find most and second most abbundant feature.
    std::array<std::uint32_t, 2u> most_abundant_rare_feature_indices{
        state.rare_features[0], state.rare_features[0]};

    std::size_t Delete = 0;

    for (std::size_t i = 0; i < state.rare_features.size(); i++) {
      std::uint32_t index2 = state.rare_features[i];
      if (state.global_feature_freqs[index2] >=
          state.global_feature_freqs[most_abundant_rare_feature_indices[0]]) {
        most_abundant_rare_feature_indices[1] =
            most_abundant_rare_feature_indices[0];
        most_abundant_rare_feature_indices[0] = index2;
        Delete = i;
      }
    }

    // Remove most abundant rare feature.
    state.rare_features[Delete] = state.rare_features.back();
    state.rare_features.pop_back();

    utils::ForEachMultiIndexValues<false>(
        corpus.corpus.template get<Sequential>(), [&](auto &input) {
          if (input.delete_feature_freq(most_abundant_rare_feature_indices[0]))
            input.needs_energy_update = true;
        });

    state.freq_of_most_abundant_rare_feature =
        state.global_feature_freqs[most_abundant_rare_feature_indices[1]];
  }

  state.rare_features.push_back(index);
  state.global_feature_freqs[index] = 0u;
  utils::ForEachMultiIndexValues<true>(
      corpus.corpus.template get<Sequential>(), [&](auto &input) {
        input.delete_feature_freq(index);

        // Apply add-one smoothing to this locally undiscovered feature.
        // Zero energy seeds will never be fuzzed and remain zero energy.
        if (input.energy > 0.0) {
          input.sum_incidence += 1;
          input.energy += lflog(input.sum_incidence) / input.sum_incidence;
        }
      });

  state.distribution_needs_update = true;
}

}  // namespace fuzzuf::algorithm::libfuzzer::feature

#endif
