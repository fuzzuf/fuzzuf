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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_DELETE_INPUT_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_DELETE_INPUT_HPP
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include <algorithm>
#include <type_traits>

namespace fuzzuf::algorithm::libfuzzer::corpus {

/**
 * @fn
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L346
 *
 * corpusからindex番目の要素を削除する
 * @tparm State libFuzzerの状態を表す型
 * @tparm Corpus 要素を削除するfull corpusの型
 * @param state libFuzzerの状態
 * @param corpus 要素を削除するcorpus
 * @param index partial corpusのindex番目の要素が削除される
 */
template <typename State, typename Corpus>
auto deleteInput(State &state, Corpus &corpus, std::size_t index)
    -> std::enable_if_t<is_state_v<State> && is_full_corpus_v<Corpus>> {
  const auto iter =
      std::next(corpus.corpus.template get<Sequential>().begin(), index);
  corpus.corpus.template get<Sequential>().modify(iter, [&](auto &input_info) {
    corpus.inputs.erase(input_info.id);
    const auto id = input_info.id;
    input_info = InputInfo();
    input_info.id = id;
    input_info.needs_energy_update = false;
  });
  state.distribution_needs_update = true;
}

} // namespace fuzzuf::algorithm::libfuzzer::corpus
#endif
