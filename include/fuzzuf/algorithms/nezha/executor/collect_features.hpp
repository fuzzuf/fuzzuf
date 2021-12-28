/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_COLLECT_FEATURES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_COLLECT_FEATURES_HPP
#include "fuzzuf/algorithms/nezha/state.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/add_feature.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/collect_features.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/update_feature_frequency.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include <type_traits>

namespace fuzzuf::algorithm::nezha::executor {

/**
 * @fn
 * 実行結果からfeatureを求める
 * libFuzzerのCollectFeaturesは入力値そのfeatureが出る最も短い入力値だった場合に、そのfeatureを実行結果のunique_featuresとするが、Nezhaでは出たfeatureは全て実行結果のunique_featuresと見做す
 * (つまりuniqueではなくなる。オリジナルの実装ではunique_featuresのuniqueを消す変更も入っている)
 *
 * Nezhaの対応箇所
 * https://github.com/nezha-dt/nezha/blob/master/Fuzzer/FuzzerLoop.cpp#L433
 *
 * @tparm State stateの型
 * @tparm Corpus corpusの型
 * @tparm Range 入力値のrangeの型
 * @tparm Cov カバレッジのrangeの型
 * @param state libFuzzerの状態
 * @param corpus 実行結果を追加する先となるcorpus
 * @param range 入力値のrange
 * @param found_unique_features
 * この値がnullptrでない場合、新しいfeatureが見つかったかどうかが返る。見つかった場合はtrue
 * @param exec_result 実行結果
 * @param cov カバレッジのrange
 * @param module_offset
 * カバレッジの先頭の要素をmodule_offset要素目と見做してfeatureの値を求める
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
                                       state.config.shrink);

        if (state.config.reduce_inputs)
          unique_feature_set_temp.push_back(f);

        if (state.config.entropic.enabled)
          libfuzzer::feature::UpdateFeatureFrequency(state, exec_result, f);

        if (state.config.reduce_inputs && !exec_result.never_reduce)
          ++found_unique_features_of_input_info;
      });
  exec_result.found_unique_features = found_unique_features_of_input_info;
  exec_result.features_count =
      state.updated_features_count - previous_updates_count;
  exec_result.unique_feature_set = unique_feature_set_temp;
}

} // namespace fuzzuf::algorithm::nezha::executor

#endif
