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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTOR_COLLECT_FEATURE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTOR_COLLECT_FEATURE_HPP
#include <algorithm>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/feature/add_feature.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/collect_features.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/update_feature_frequency.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

namespace fuzzuf::algorithm::libfuzzer::executor {

/**
 * Calculate features of specified execution result.
 * "Feature" is a outstanding feature of the execution which has unique ID. In
 * most case, entering a new edge that is not covered by previous executions is
 * a feature. "Features" is a vector of feature. libFuzzer calculate weight of
 * the execution result that affects by features. If ChooseRandomSeed is using
 * non-uniform distribution, input of higher weighted execution result is
 * selected more frequentry.
 * @tparam State LibFuzzer state object type
 * @tparam Corpus FullCorpus type to add new execution result
 * @tparam Range Contiguous Range of std::uint8_t to pass input
 * @tparam InputInfo Type to provide execution result
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
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus> &&
                        is_input_info_v<InputInfo> &&
                        utils::range::is_range_of_v<Range, std::uint8_t> &&
                        utils::range::has_data_v<Range>> {
  utils::type_traits::RemoveCvrT<decltype(exec_result.unique_feature_set)>
      unique_feature_set_temp;
  std::size_t found_unique_features_of_input_info = 0u;
  size_t previous_updates_count = state.updated_features_count;
  const auto size = utils::range::rangeSize(range);
  feature::CollectFeatures(state, cov, module_offset, [&](auto f) -> void {
    if (feature::AddFeature(state, corpus, f, static_cast<std::uint32_t>(size),
                            state.create_info.config.shrink))
      unique_feature_set_temp.push_back(f);

    if (state.create_info.config.entropic.enabled)
      feature::UpdateFeatureFrequency(state, exec_result, f);

    if (state.create_info.config.reduce_inputs && !exec_result.never_reduce)
      if (std::binary_search(exec_result.unique_feature_set.begin(),
                             exec_result.unique_feature_set.end(), f))
        ++found_unique_features_of_input_info;
  });
  exec_result.found_unique_features = found_unique_features_of_input_info;
  exec_result.features_count =
      state.updated_features_count - previous_updates_count;
  exec_result.unique_feature_set = unique_feature_set_temp;
}

}  // namespace fuzzuf::algorithm::libfuzzer::executor

#endif
