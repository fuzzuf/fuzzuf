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
 * @file collect_features.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_COLLECT_FEATURES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_COLLECT_FEATURES_HPP
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/feature/add_feature.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/collect_features.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/update_feature_frequency.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/algorithms/nezha/state.hpp"
#include "fuzzuf/utils/range_traits.hpp"

namespace fuzzuf::algorithm::nezha::executor {

/**
 * Calculate features of specified execution result.
 * Unlike CollectFeatures in libFuzzer, this function consider every features
 * detected on the execution as unique_features of the execution. (This means
 * unique_features is no longer unique. As the Reflection of that difference,
 * original Nezha implementation renames unique_features to features.)
 *
 * Corresponding code of original Nezha implementation
 * https://github.com/nezha-dt/nezha/blob/master/Fuzzer/FuzzerLoop.cpp#L433
 *
 * @tparam State LibFuzzer state object type
 * @tparam Corpus FullCorpus type to add new execution result
 * @tparam Range Contiguous Range of std::uint8_t to pass input
 * @tparam Cov Range of std::uint8_t to pass coverage
 * @param state LibFuzzer state object
 * @param corpus FullCorpus to add new execution result
 * @param range Input value that was passed to the executor
 * @param exec_result Execution result that was produced by the executor
 * @param cov Coverage retrived from the executor
 * @param module_offset Offset value of feature. if module_offset is 3000 and
 * cov[ 2 ] is non zero value, the feature 3002 is activated.
 */
template <typename State, typename Corpus, typename Range, typename InputInfo,
          typename Cov>
auto CollectFeatures(State &state, Corpus &corpus, Range &range,
                     InputInfo &exec_result, Cov &cov,
                     std::uint32_t module_offset)
    -> std::enable_if_t<libfuzzer::is_state_v<State> &&
                        libfuzzer::is_full_corpus_v<Corpus> &&
                        utils::range::is_range_of_v<Range, std::uint8_t> &&
                        utils::range::has_data_v<Range> &&
                        utils::range::is_range_of_v<Cov, std::uint8_t> &&
                        utils::range::has_data_v<Cov>> {
  utils::type_traits::RemoveCvrT<decltype(exec_result.unique_feature_set)>
      unique_feature_set_temp;
  std::size_t found_unique_features_of_input_info = 0u;
  size_t previous_updates_count = state.updated_features_count;
  const auto size = utils::range::rangeSize(range);
  libfuzzer::feature::CollectFeatures(
      state, cov, module_offset, [&](auto f) -> void {
        libfuzzer::feature::AddFeature(state, corpus, f,
                                       static_cast<std::uint32_t>(size),
                                       state.create_info.config.shrink);

        if (state.create_info.config.reduce_inputs)
          unique_feature_set_temp.push_back(f);

        if (state.create_info.config.entropic.enabled)
          libfuzzer::feature::UpdateFeatureFrequency(state, exec_result, f);

        if (state.create_info.config.reduce_inputs && !exec_result.never_reduce)
          ++found_unique_features_of_input_info;
      });
  exec_result.found_unique_features = found_unique_features_of_input_info;
  exec_result.features_count =
      state.updated_features_count - previous_updates_count;
  exec_result.unique_feature_set = unique_feature_set_temp;
}

}  // namespace fuzzuf::algorithm::nezha::executor

#endif
