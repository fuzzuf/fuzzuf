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
 * @file add_to_corpus.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTOR_ADD_TO_CORPUS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTOR_ADD_TO_CORPUS_HPP
#include <algorithm>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/corpus/add_to_corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/corpus/replace_corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/utils/range_traits.hpp"

namespace fuzzuf::algorithm::libfuzzer::executor {

/**
 * Insert execution result to corpus if that has features
 * Note that, CollectFeatures must be applied to the execution result ahead, or
 * the feature count is left to 0, and added result will never be selected by
 * ChooseRandom Seed.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerLoop.cpp#L525
 *
 * @tparam State LibFuzzer state object type
 * @tparam Corpus FullCorpus type to add new execution result
 * @tparam Range Contiguous Range of std::uint8_t
 * @tparam InputInfo Type to provide execution result
 * @param state LibFuzzer state object
 * @param corpus FullCorpus to add new execution result
 * @param range Input value that was passed to the executor
 * @param exec_result Execution result that was produced by the executor
 * @param force_add_to_corpus If true, the execution result is added to the
 * corpus regardless of features. Otherwise, the execution result is added to
 * the corpus if the execution found novel features.
 * @param may_delete_file Set may_delete_file attribute to the execution result
 * ( This attribute is not used in current fuzzuf's implementation ).
 * @param persistent If true, the input is written to both memory and storage.
 * Otherwise, the input is stored on the memory only.
 * @param strict_match If true, the execution result with completely same unique
 * feature set to existing result causes REPLACE. Otherwise, the execution
 * result with same length of unique feature set to existing result causes
 * REPLACE.
 * @param path_prefix Directory to store inputs if persistent is true.
 * @param sink Callback function with one string argument to output messages.
 */
template <typename State, typename Corpus, typename Range, typename InputInfo>
auto AddToCorpus(State &state, Corpus &corpus, Range &range,
                 InputInfo &exec_result, bool force_add_to_corpus,
                 bool may_delete_file, bool persistent, bool strict_match,
                 const fs::path &path_prefix,
                 const std::function<void(std::string &&)> &sink)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus> &&
                            is_input_info_v<InputInfo> &&
                            utils::range::is_range_of_v<Range, std::uint8_t> &&
                            utils::range::has_data_v<Range>,
                        bool> {
  if (exec_result.features_count || force_add_to_corpus) {
    exec_result.never_reduce = force_add_to_corpus;
    exec_result.may_delete_file = may_delete_file;
    exec_result.has_focus_function = false;  // TPC.ObservedFocusFunction();
    exec_result.needs_energy_update = false;

    // Assign maximal energy to the new seed.
    exec_result.energy =
        state.rare_features.empty() ? 1.0 : log(state.rare_features.size());
    exec_result.sum_incidence = static_cast<double>(state.rare_features.size());
    exec_result.needs_energy_update = false;
    // TPC.UpdateObservedPCs();

    exec_result.added_to_corpus = exec_result.features_count;
    corpus::AddToCorpus(corpus, range, exec_result, persistent, path_prefix);
    /*
        WriteFeatureSetToFile(Options.FeaturesDir, Sha1ToString(NewII->Sha1),
            NewII->UniqFeatureSet);
        WriteEdgeToMutationGraphFile(Options.MutationGraphFile, NewII, II,
            MD.MutationSequence());
    */

    state.distribution_needs_update = true;
    return true;
  }

  if (exec_result && exec_result.found_unique_features &&
      //    II->DataFlowTraceForFocusFunction.empty() && // DFT is not supported
      //    on this implementation
      exec_result.found_unique_features ==
          exec_result.unique_feature_set.size() &&
      exec_result.input_size > utils::range::rangeSize(range)) {
    auto &hashed = corpus.corpus.template get<libfuzzer::ById>();
    auto existing = hashed.find(exec_result.id);
    if (!strict_match || (existing != hashed.end() &&
                          std::equal(existing->unique_feature_set.begin(),
                                     existing->unique_feature_set.end(),
                                     exec_result.unique_feature_set.begin(),
                                     exec_result.unique_feature_set.end()))) {
      if (state.create_info.config.feature_debug) {
        std::string message("Replace: ");
        utils::toString(message, exec_result.input_size);
        message += " => ";
        utils::toString(message, utils::range::rangeSize(range));
        message += "\n";
        sink(std::move(message));
      }
      exec_result.never_reduce = force_add_to_corpus;
      exec_result.may_delete_file = may_delete_file;
      exec_result.has_focus_function = false;  // TPC.ObservedFocusFunction();
      exec_result.needs_energy_update = false;

      // Assign maximal energy to the new seed.
      exec_result.energy =
          state.rare_features.empty() ? 1.0 : log(state.rare_features.size());
      exec_result.sum_incidence =
          static_cast<double>(state.rare_features.size());
      exec_result.needs_energy_update = false;
      exec_result.added_to_corpus = true;
      corpus::replaceCorpus(corpus, range, exec_result, persistent,
                            path_prefix);
      return true;
    }
  }
  exec_result.added_to_corpus = false;
  return false;
}

}  // namespace fuzzuf::algorithm::libfuzzer::executor

#endif
