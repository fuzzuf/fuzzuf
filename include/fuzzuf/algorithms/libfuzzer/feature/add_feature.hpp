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
 * @file add_feature.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_ADD_FEATURE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_ADD_FEATURE_HPP
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/corpus/delete_input.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/add_rare_feature.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/algorithms/libfuzzer/utils.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::feature {

/**
 * Append feature
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L409
 *
 * @tparam State LibFuzzer state object type
 * @tparam Corpus FullCorpus type to add new execution result
 * @param state LibFuzzer state object
 * @param corpus FullCorpus
 * @param index Feature ID to add
 * @param new_size Length of input which produced this feature
 * @param shrink If true and the input value is shorter than known input value
 * producing this feature ID, existing input value is removed from the corpus.
 */
template <typename State, typename Corpus>
auto AddFeature(State &state, Corpus &corpus, size_t index,
                std::uint32_t new_size, bool shrink)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus>, bool> {
  assert(new_size);
  index = index % utils::range::rangeSize(state.input_sizes_per_feature);
  std::uint32_t old_size = state.input_sizes_per_feature[index];

  if (old_size == 0 || (shrink && old_size > new_size)) {
    if (old_size > 0) {
      std::size_t old_index = state.smallest_element_per_feature[index];
      auto iter = std::next(corpus.corpus.template get<Sequential>().begin(),
                            old_index);
      bool drop = false;
      corpus.corpus.template get<Sequential>().modify(
          iter, [&](auto &testcase) {
            if (testcase) {
              assert(testcase.features_count > 0);
              testcase.features_count--;
              if (testcase.features_count == 0) drop = true;
            }
          });
      if (drop)
        ::fuzzuf::algorithm::libfuzzer::corpus::deleteInput(state, corpus,
                                                            old_index);
    } else {
      ++state.added_features_count;
      if (state.create_info.config.entropic.enabled)
        AddRareFeature(state, corpus, index);
    }
    ++state.updated_features_count;
    // Inputs.size() is guaranteed to be less than UINT32_MAX by AddToCorpus.
    state.smallest_element_per_feature[index] =
        static_cast<uint32_t>(corpus.corpus.size());
    state.input_sizes_per_feature[index] = new_size;
    return true;
  }
  return false;
}

}  // namespace fuzzuf::algorithm::libfuzzer::feature

#endif
