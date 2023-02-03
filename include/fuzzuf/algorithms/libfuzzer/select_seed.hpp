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
 * @file select_seed.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_SELECT_SEED_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_SELECT_SEED_HPP
#include <boost/range/iterator_range.hpp>

#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/utils/for_each_multi_index_values.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/void_t.hpp"

namespace fuzzuf::algorithm::libfuzzer::select_seed {

/**
 * Display feature count and weight of current corpus elements in libFuzzer
 * compatible format
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L547
 *
 * @tparam Corpus Type of corpus
 * @param corpus Display elements of this corpus
 * @param weights Weights of each corpus elements
 * @param sink Callable with one string argument to display message
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

/**
 * Generate sequentially increasing integer range in size of corpus
 *
 * @tparam Corpus Type of corpus
 * @param corpus Corpus to retrive the size
 * @param intervals Destination container
 */
template <typename Corpus>
auto GenerateIntervals(Corpus &corpus, std::vector<double> &intervals)
    -> std::enable_if_t<is_full_corpus_v<Corpus>> {
  const std::size_t corpus_size = corpus.corpus.size();
  intervals.resize(corpus_size + 1u);
  std::iota(intervals.begin(), intervals.end(), 0);
}

/**
 * Generate weights whose newer elements are more frequently chosen.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L540
 *
 * @tparam Corpus Type of corpus
 * @param corpus Generate weights for elements of this corpus
 * @param intervals Callable with one string argument to display message
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

/**
 * Calculate energy for each corpus element, then decide weights depending on
 * the energy.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L504
 *
 * @tparam Corpus Type of corpus
 * @param corpus Generate weights for elements of this corpus
 * @param intervals Callable with one string argument to display message
 */
template <typename State, typename Corpus>
auto GenerateEntropicSchedule(State &state, Corpus &corpus,
                              std::vector<double> &weights,
                              std::uint8_t max_mutation_factor)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus>, bool> {
  if (!state.create_info.config.entropic.enabled) return false;
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
          input.updateEnergy(
              state.rare_features.size(),
              state.create_info.config.entropic.scale_per_exec_time,
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
        if (weights.back() > 0.0) vanilla_schedule = false;
      });
  return !vanilla_schedule;
}

/**
 * Update distribution that is used to choose input value.
 * Compatible to LLVM version equal or higher than 11.0.0 ( entropic mode is
 * enabled )
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L488
 *
 * @tparam llvm_version LLVM version that the function is about to compatible
 * to.
 * @tparam State LibFuzzer state object type
 * @tparam Corpus FullCorpus type to add new execution result
 * @tparam RNG A type that satisfies standard  random number generator concept
 * @param state LibFuzzer state object
 * @param corpus FullCorpus to add new execution result
 * @param rng Random number generator
 * @param sparse_energy_updates
 * On entropic mode, calculate distribution in probability of
 * 1/sparse_energy_updates even if distribution updating is not requested.
 * @param sink Callable with one string argument to display message
 */
template <Version llvm_version, typename State, typename Corpus, typename RNG>
auto UpdateDistribution(State &state, Corpus &corpus, RNG &rng,
                        std::size_t sparse_energy_updates,
                        std::uint8_t max_mutation_factor,
                        const std::function<void(std::string &&)> &sink)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus> &&
                            (llvm_version >= MakeVersion(11u, 0u, 0u)),
                        bool> {
  if (!state.distribution_needs_update &&
      (!state.create_info.config.entropic.enabled ||
       random_value(rng, sparse_energy_updates)))
    return false;

  state.distribution_needs_update = false;
  size_t corpus_size = corpus.corpus.size();
  assert(corpus_size);
  std::vector<double> intervals;
  GenerateIntervals(corpus, intervals);
  std::vector<double> weights;

  bool vanilla_schedule = true;
  if (state.create_info.config.entropic.enabled)
    vanilla_schedule =
        !GenerateEntropicSchedule(state, corpus, weights, max_mutation_factor);

  if (vanilla_schedule) GenerateVanillaSchedule(corpus, weights);

  if (state.create_info.config.debug) DumpDistribution(corpus, weights, sink);

  if (std::find_if(weights.begin(), weights.end(),
                   [](auto v) { return v != 0; }) == weights.end())
    std::fill(weights.begin(), weights.end(), 1);

  state.corpus_distribution = std::piecewise_constant_distribution<double>(
      intervals.begin(), intervals.end(), weights.begin());
  return true;
}

/**
 * Update distribution that is used to choose input value.
 * Compatible to LLVM version less than 11.0.0 ( entropic mode is enabled )
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-10.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L271
 *
 * @tparam llvm_version LLVM version that the function is about to compatible
 * to.
 * @tparam State LibFuzzer state object type
 * @tparam Corpus FullCorpus type to add new execution result
 * @tparam RNG A type that satisfies standard  random number generator concept
 * @param state LibFuzzer state object
 * @param corpus FullCorpus to add new execution result
 * @param rng Random number generator
 * @param sparse_energy_updates
 * On entropic mode, calculate distribution in probability of
 * 1/sparse_energy_updates even if distribution updating is not requested.
 * @param sink Callable with one string argument to display message
 */
template <Version llvm_version, typename State, typename Corpus, typename RNG>
auto UpdateDistribution(State &state, Corpus &corpus, RNG &, std::size_t,
                        std::uint8_t,
                        const std::function<void(std::string &&)> &sink)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus> &&
                            (State::llvm_version < MakeVersion(11u, 0u, 0u)),
                        bool> {
  size_t corpus_size = corpus.corpus.size();
  assert(corpus_size);
  std::vector<double> intervals(corpus_size + 1u);
  std::iota(intervals.begin(), intervals.end(), 0);
  std::vector<double> weights;
  GenerateVanillaSchedule(corpus, weights);
  if (state.create_info.config.debug) {
    DumpDistribution(corpus, weights, sink);
  }
  state.corpus_distribution = std::piecewise_constant_distribution<double>(
      intervals.begin(), intervals.end(), weights.begin());
  return true;
}

/**
 * Choose one input value from the corpus, then copy it to the range
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L297
 * and
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L303
 *
 * @tparam State LibFuzzer state object type
 * @tparam Corpus FullCorpus type to add new execution result
 * @tparam RNG A type that satisfies standard  random number generator concept
 * @tparam Range Container of std::uint8_t to store selected input value
 * @tparam InputInfo Type to store execution result of selected corpus element
 * @param state LibFuzzer state object
 * @param corpus FullCorpus to add new execution result
 * @param rng Random number generator
 * @param range Selected input value is stored in this value
 * @param exec_result Selected execution result is stored in this value
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
    const exec_input::ExecInput &selected_input =
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

}  // namespace fuzzuf::algorithm::libfuzzer::select_seed

#endif
