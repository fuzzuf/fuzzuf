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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_ADD_TO_CORPUS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_ADD_TO_CORPUS_HPP
#include "fuzzuf/algorithms/libfuzzer/executor/add_to_corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class AddToCorpus
 * @brief Insert execution result to corpus if that has features
 * Note that, CollectFeatures must be applied to the execution result ahead, or
 * the feature count is left to 0, and added result will never be selected by
 * ChooseRandom Seed. The node takes 4 paths for state, corpus, input and
 * exec_result.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
class AddToCorpus {};
template <typename R, typename... Args, typename Path>
class AddToCorpus<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param force_add_to_corpus_
   * If true, execution result is inserted to corpus even if no features were
   * detected. Otherwise, only results with detected features  are inserted.
   * @param may_delete_file_
   * Add may_delete_file attribute to the execution result. This attribute is
   * not used in current fuzzuf's implementation of libFuzzer.
   * @param persistent_ Write input to storage.
   * @param strict_match
   * If True, execution result which has exactly same features in
   * unique_feature_set causes to existing one causes "replace". Otherwise,
   * execution result which has same number of features in unique_feature_set
   * causes "replace".
   */
  AddToCorpus(bool force_add_to_corpus_, bool may_delete_file_,
              bool persistent_, bool strict_match_,
              const fs::path &path_prefix_,
              std::function<void(std::string &&)> &&sink_)
      : force_add_to_corpus(force_add_to_corpus_),
        may_delete_file(may_delete_file_),
        persistent(persistent_),
        strict_match(strict_match_),
        path_prefix(path_prefix_),
        sink(std::move(sink_)) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("AddToCorpus", enter)
    Path()(
        [&](auto &&...sorted) {
          executor::AddToCorpus(sorted..., force_add_to_corpus, may_delete_file,
                                persistent, strict_match, path_prefix, sink);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(AddToCorpus)
  }

 private:
  bool force_add_to_corpus;
  bool may_delete_file;
  bool persistent;
  bool strict_match;
  fs::path path_prefix;
  std::function<void(std::string &&)> sink;
};
namespace standard_order {
template <typename T>
using AddToCorpusStdArgOrderT =
    decltype(T::state && T::corpus && T::input && T::exec_result);
template <typename F, typename Ord>
using AddToCorpus = libfuzzer::AddToCorpus<F, AddToCorpusStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
