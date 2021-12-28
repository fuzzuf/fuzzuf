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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_REPLACE_CORPUS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_REPLACE_CORPUS_HPP
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/sha1.hpp"
#include <algorithm>
#include <cassert>
#include <type_traits>

namespace fuzzuf::algorithm::libfuzzer::corpus {

/**
 * @fn
 * corpusにある実行結果を置き換える
 * 入力値にはIDが振られ、corpus.inputsに追加される
 * corpus.corpusのtestcase_.idのidを持つ要素がtestcase_の内容に書き変わる
 *
 * @tparm persistent trueの場合永続化する
 * @tparm Corpus full corpusの型
 * @tparm Range 入力値の型
 * @param corpus 入力を追加する先のcorpus
 * @param range 入力値
 * @param testcase_ 入力値に対応する実行結果
 */
template <typename Corpus, typename Range, typename InputInfo>
auto replaceCorpus(Corpus &corpus, Range &range, InputInfo &testcase_,
                   bool persistent, const fs::path &path_prefix)
    -> std::enable_if_t<is_full_corpus_v<Corpus> &&
                        is_input_info_v<InputInfo>> {
  assert(!utils::range::rangeEmpty(range));
  // Inputs.size() is cast to uint32_t below.
  assert(corpus.corpus.size() < std::numeric_limits<uint32_t>::max());

  std::uint64_t id = 0u;
  testcase_.sha1 = utils::ToSerializedSha1(range);
  testcase_.input_size = utils::range::rangeSize(range);
  if (testcase_.name.empty())
    testcase_.name = testcase_.sha1;
  const auto old_id = testcase_.id;
  auto &hashed = corpus.corpus.template get<ById>();
  const auto existing = hashed.find(old_id);
  if (existing != hashed.end()) {
    corpus.inputs.erase(old_id);
  }
  if (!persistent) {
    auto exec_input = corpus.inputs.CreateOnMemory(
        range.data(), utils::range::rangeSize(range));
    assert(exec_input);
    id = exec_input->GetID();
  } else {
    auto exec_input =
        corpus.inputs.CreateOnDisk(path_prefix / fs::path(testcase_.name));
    assert(exec_input);
    exec_input->OverwriteThenUnload(range.data(),
                                    utils::range::rangeSize(range));
    id = exec_input->GetID();
  }
  testcase_.id = id;
  std::sort(testcase_.unique_feature_set.begin(),
            testcase_.unique_feature_set.end());
  if (existing != hashed.end()) {
    testcase_.reduced = true;
    hashed.replace(existing, testcase_);
  } else
    hashed.insert(testcase_);
}

} // namespace fuzzuf::algorithm::libfuzzer::corpus

#endif
