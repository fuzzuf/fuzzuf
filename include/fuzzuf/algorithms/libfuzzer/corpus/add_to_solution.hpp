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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_ADD_TO_SOLUTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_ADD_TO_SOLUTION_HPP
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/utils/sha1.hpp"
#include <algorithm>
#include <cassert>
#include <fstream>
#include <iterator>
#include <type_traits>

namespace fuzzuf::algorithm::libfuzzer::corpus {

/**
 * @fn
 * corpusに入力値を追加する
 * 入力値にはIDが振られ、corpus.inputsに追加される
 * corpus.corpusには入力値のIDと実行結果が追加される
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L208
 *
 * @tparm persistent trueの場合永続化する
 * @tparm Corpus full corpusの型
 * @tparm Range 入力値の型
 * @param corpus 入力を追加する先のcorpus
 * @param range 入力値
 * @param testcase_ 入力値に対応する実行結果
 */
template <typename Range, typename InputInfo>
auto AddToSolution(Range &range, InputInfo &testcase_,
                   const fs::path &path_prefix)
    -> std::enable_if_t<is_input_info_v<InputInfo>> {

  assert(!utils::range::rangeEmpty(range));

  testcase_.sha1 = utils::ToSerializedSha1(range);
  testcase_.input_size = utils::range::rangeSize(range);
  if (testcase_.name.empty())
    testcase_.name = testcase_.sha1;
  std::ofstream fd((path_prefix / fs::path(testcase_.name)).string(),
                   std::ios::out | std::ios::binary);
  std::copy(range.begin(), range.end(), std::ostreambuf_iterator(fd));
}

} // namespace fuzzuf::algorithm::libfuzzer::corpus

#endif
