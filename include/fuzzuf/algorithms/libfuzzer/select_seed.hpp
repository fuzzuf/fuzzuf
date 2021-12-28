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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_SELECT_SEED_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_SELECT_SEED_HPP
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/for_each_multi_index_values.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/void_t.hpp"
#include <boost/range/iterator_range.hpp>

namespace fuzzuf::algorithm::libfuzzer::select_seed {

/*
 * @fn
 * 現在のcorpusの各要素のfeatureの数と重みを出力する
 * 出力のフォーマットはlibFuzzer互換
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L547
 *
 * @tparm Corpus corpusの型
 * @param corpus このcorpusの中身が出力される
 * @param weights corpusの各要素の重み
 * @param sink メッセージの出力先
 */
template <typename Corpus>
auto DumpDistribution(Corpus &corpus, const std::vector<double> &weights,
                      const std::function<void(std::string &&)> &sink)
    -> std::enable_if_t<is_full_corpus_v<Corpus>> {
  std::string message;
  for (const auto &input : corpus.corpus) {
    message += std::to_string(input.features_count);
    message += ' ';
  }
  message += "SCORE\n";
  for (const auto &w : weights) {
    message += std::to_string(w);
    message += ' ';
  }
  message += "Weights\n";
  sink(std::move(message));
}

/*
 * @fn
 * corpusの要素数と同サイズの整数の列を作る
 *
 *
 *
 * @tparm Corpus corpusの型
 * @param corpus このcorpusの要素数が使用される
 * @param intervals 出力先
 */
template <typename Corpus>
auto GenerateIntervals(Corpus &corpus, std::vector<double> &intervals)
    -> std::enable_if_t<is_full_corpus_v<Corpus>> {
  const std::size_t corpus_size = corpus.corpus.size();
  intervals.resize(corpus_size + 1u);
  std::iota(intervals.begin(), intervals.end(), 0);
}

/*
 * @fn
 * corpusの後ろの要素ほど選ばれやすい重みを生成する
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L540
 *
 * @tparm Corpus corpusの型
 * @param corpus このcorpusの要素数が使用される
 * @param intervals 出力先
 */
template <typename Corpus>
auto GenerateVanillaSchedule(Corpus &corpus, std::vector<double> &weights)
    -> std::enable_if_t<is_full_corpus_v<Corpus>> {
  const std::size_t corpus_size = corpus.corpus.size();
  std::size_t i = 0u;
  weights.clear();
  weights.reserve(corpus_size);
  utils::ForEachMultiIndexValues<false>(
      corpus.corpus.template get<Sequential>(), [&](auto &input) {
        weights.push_back(
            input.features_count
                ? static_cast<double>((i + 1) *
                                      (input.has_focus_function ? 1000 : 1))
                : 0.);
        input.weight = weights.back();
        ++i;
      });
}

/*
 * @fn
 * testcaseのenergyを求めて、energyに基づいて重みを生成する
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L504
 *
 * @tparm Corpus corpusの型
 * @param corpus このcorpusの要素数が使用される
 * @param intervals 出力先
 */
template <typename State, typename Corpus>
auto GenerateEntropicSchedule(State &state, Corpus &corpus,
                                std::vector<double> &weights,
                                std::uint8_t max_mutation_factor)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus>, bool> {
  if (!state.config.entropic.enabled)
    return false;
  const std::size_t corpus_size = corpus.corpus.size();
  weights.reserve(corpus_size);
  const auto average_unit_execution_time =
      std::accumulate(corpus.corpus.begin(), corpus.corpus.end(),
                      std::chrono::microseconds(0),
                      [](auto sum, const auto &input) {
                        return sum + input.time_of_unit;
                      }) /
      corpus_size;
  bool vanilla_schedule = true;
  utils::ForEachMultiIndexValues<true>(
      corpus.corpus.template get<Sequential>(), [&](auto &input) {
        if (input.needs_energy_update && input.energy != 0.0) {
          input.needs_energy_update = false;
          input.updateEnergy(state.rare_features.size(),
                             state.config.entropic.scale_per_exec_time,
                             average_unit_execution_time);
        }
      });
  utils::ForEachMultiIndexValues<false>(
      corpus.corpus.template get<Sequential>(), [&](auto &input) {
        if (input.features_count == 0) {
          // If the seed doesn't represent any features, assign zero energy.
          weights.push_back(0.);
        } else if (input.executed_mutations_count / max_mutation_factor >
                   state.executed_mutations_count / corpus.corpus.size()) {
          // If the seed was fuzzed a lot more than average, assign zero energy.
          weights.push_back(0.);
        } else {
          // Otherwise, simply assign the computed energy.
          weights.push_back(input.energy);
        }
        input.weight = weights.back();

        // If energy for all seeds is zero, fall back to vanilla schedule.
        if (weights.back() > 0.0)
          vanilla_schedule = false;
      });
  return !vanilla_schedule;
}

/*
 * @fn
 * 入力の選択に使う重みを更新する
 * LLVM 10.0.0 以上版( entropicモードを使う )
 *
 * libFuzzer
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L488
 *
 * @tparm llvm_version LLVMのバージョン
 * @tparm State libFuzzerの状態を表す型
 * @tparm Corpus corpusの型
 * @tparm RNG 乱数生成器の型
 * @param state libFuzzerの状態
 * @param corpus このcorpusの要素に対する重みが計算される
 * @param rng 乱数生成器
 * @param sparse_energy_updates
 * entropicモードの場合、分布の更新が不要な状況でも1/sparse_energy_updatesの確率で分布の更新を行う
 * @param sink メッセージの出力先
 */
template <Version llvm_version, typename State, typename Corpus, typename RNG>
auto UpdateDistribution(State &state, Corpus &corpus, RNG &rng,
                        std::size_t sparse_energy_updates,
                        std::uint8_t max_mutation_factor,
                        const std::function<void(std::string &&)> &sink)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus> &&
                            (llvm_version >= MakeVersion(10u, 0u, 0u)),
                        bool> {
  if (!state.distribution_needs_update &&
      (!state.config.entropic.enabled ||
       random_value(rng, sparse_energy_updates)))
    return false;

  state.distribution_needs_update = false;
  size_t corpus_size = corpus.corpus.size();
  assert(corpus_size);
  std::vector<double> intervals;
  GenerateIntervals(corpus, intervals);
  std::vector<double> weights;

  bool vanilla_schedule = true;
  if (state.config.entropic.enabled)
    vanilla_schedule = !GenerateEntropicSchedule(state, corpus, weights,
                                                   max_mutation_factor);

  if (vanilla_schedule)
    GenerateVanillaSchedule(corpus, weights);

  if (state.config.debug)
    DumpDistribution(corpus, weights, sink);

  if (std::find_if(weights.begin(), weights.end(),
                   [](auto v) { return v != 0; }) == weights.end())
    std::fill(weights.begin(), weights.end(), 1);

  state.corpus_distribution = std::piecewise_constant_distribution<double>(
      intervals.begin(), intervals.end(), weights.begin());
  return true;
}

/*
 * @fn
 * 入力の選択に使う重みを更新する
 * LLVM 10.0.0 未満版( entropicモードを使わない )
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-10.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L271
 *
 * @tparm llvm_version LLVMのバージョン
 * @tparm State libFuzzerの状態を表す型
 * @tparm Corpus corpusの型
 * @tparm RNG 乱数生成器の型
 * @param state libFuzzerの状態
 * @param corpus このcorpusの要素に対する重みが計算される
 * @param rng 乱数生成器
 * @param sink メッセージの出力先
 */
template <Version llvm_version, typename State, typename Corpus, typename RNG>
auto UpdateDistribution(State &state, Corpus &corpus, RNG &, std::size_t,
                        std::uint8_t,
                        const std::function<void(std::string &&)> &sink)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus> &&
                            (State::llvm_version < MakeVersion(10u, 0u, 0u)),
                        bool> {
  size_t corpus_size = corpus.corpus.size();
  assert(corpus_size);
  std::vector<double> intervals(corpus_size + 1u);
  std::iota(intervals.begin(), intervals.end(), 0);
  std::vector<double> weights;
  GenerateVanillaSchedule(corpus, weights);
  if (state.config.debug) {
    DumpDistribution(corpus, weights, sink);
  }
  state.corpus_distribution = std::piecewise_constant_distribution<double>(
      intervals.begin(), intervals.end(), weights.begin());
  return true;
}

/*
 * @fn
 * corpusから入力を1つ選び、rangeにコピーする
 * 入力は重み付きの乱数で選択される
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L297
 * および
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L303
 *
 * @tparm State libFuzzerの状態を表す型
 * @tparm Corpus corpusの型
 * @tparm RNG 乱数生成器の型
 * @tparm Range 選択した入力をコピーする先のコンテナの型
 * @tparm InputInfo 選択した入力の実行結果をコピーする先の型
 * @param state libFuzzerの状態
 * @param corpus このcorpusの要素に対する重みが計算される
 * @param rng 乱数生成器
 * @param range 選択した入力のコピー先
 * @param exec_result 選択した入力の実行結果のコピー先
 */
template <typename State, typename RNG, typename Corpus, typename Range,
          typename InputInfo>
auto SelectSeed(State &state, Corpus &corpus, RNG &rng, Range &range,
                InputInfo &exec_result, bool uniform_dist)
    -> std::enable_if_t<
        is_state_v<State> && is_full_corpus_v<Corpus> &&
            is_input_info_v<InputInfo> &&
            utils::range::is_range_of_v<Range, std::uint8_t>,
        utils::void_t<decltype(utils::range::assign(
            std::declval<boost::iterator_range<std::uint8_t *>>(),
            std::declval<Range &>()))>> {
  std::size_t index = 0u;
  if (uniform_dist)
    index = random_value(rng, corpus.corpus.size());
  else {
    auto &dist = state.corpus_distribution;
    index = dist(rng);
  }
  assert(index < corpus.corpus.size());
  auto selected_testcase = std::next(corpus.corpus.begin(), index);
  if (selected_testcase->enabled) {
    const ExecInput &selected_input =
        *corpus.inputs.get_ref(selected_testcase->id);
    const auto *head = selected_input.GetBuf();
    const auto length = selected_input.GetLen();
    utils::range::assign(
        boost::make_iterator_range(head, std::next(head, length)), range);
    exec_result = InputInfo();
    exec_result.executed_mutations_count =
        selected_testcase->executed_mutations_count;
  } else {
    range.clear();
    exec_result = InputInfo();
    exec_result.executed_mutations_count =
        selected_testcase->executed_mutations_count;
  }
}

} // namespace fuzzuf::algorithm::libfuzzer::select_seed

#endif
