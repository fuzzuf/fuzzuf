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
/**
 * @file select_seed.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/libfuzzer/select_seed.hpp"
#include "fuzzuf/utils/for_each_multi_index_values.hpp"
namespace fuzzuf::algorithm::libfuzzer::select_seed {

/**
 * Display feature count and weight of current corpus elements in libFuzzer compatible format
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L547
 *
 * @param corpus Display elements of this corpus
 * @param weights Weights of each corpus elements
 * @param sink Callable with one string argument to display message
 */
void dumpDistribution(FullCorpus &corpus, const std::vector<double> &weights,
                      const std::function<void(std::string &&)> &sink) {
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
 * Generate integer sequence with same size to corpus
 *
 * @param corpus The source corpus
 * @param intervals Destination
 */
void generateIntervals(FullCorpus &corpus, std::vector<double> &intervals) {
  const std::size_t corpus_size = corpus.corpus.size();
  intervals.resize(corpus_size + 1u);
  std::iota(intervals.begin(), intervals.end(), 0);
}

/**
 * Generate distribution that select newer elements in higher probability.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L540
 *
 * @param corpus The weight is generated for the elements of this corpus
 * @param intervals Destination
 */
void generateVanillaSchedule(FullCorpus &corpus, std::vector<double> &weights) {
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

} // namespace fuzzuf::algorithm::libfuzzer::select_seed
