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
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_ADD_TO_SOLUTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_ADD_TO_SOLUTION_HPP
#include "fuzzuf/algorithms/nezha/state.hpp"
#include "fuzzuf/algorithms/libfuzzer/corpus/add_to_solution.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/to_string.hpp"
#include <type_traits>

namespace fuzzuf::algorithm::nezha::executor {

/**
 * @fn
 * outputsが未知の標準出力の組み合わせの場合または一部のターゲットのカバレッジだけに新規性が見られた場合、かつターゲット間で標準出力に差が見られる場合に実行結果と入力値に名前をつけて指定されたcorpusに追加する
 *
 * @tparm Corpus corpusの型
 * @tparm Range 入力値の型
 * @param corpus このcorpusに実行結果を追加する
 * @param range この入力値を追加する
 * @param exec_result この実行結果を追加する
 * @param trace
 * 各ターゲットの実行結果がAddToCorpusでcorpusに追加されたかどうかを表すboolのrange
 * @param known_traces
 * 過去にadd_to_solutionsを呼び出した際に渡ってきた事があるtraceのset
 * @param outputs
 * 各ターゲットを実行した際に得られた標準出力のハッシュを並べたstd::size_tのrange
 * @param outputs_hash
 * 過去にAddToSolutionsを呼び出した際に渡ってきた事があるoutputsのset
 * @param path_prefix 出力先のディレクトリ
 */
template <typename Range, typename Output>
auto AddToSolution(Range &range, libfuzzer::InputInfo &exec_result,
                   const trace_t &trace, known_traces_t &trace_hash,
                   const Output &outputs, known_outputs_t &outputs_hash,
                   const fs::path &path_prefix)
    -> std::enable_if_t<utils::range::is_range_of_v<Range, std::uint8_t> &&
                            utils::range::has_data_v<Range>,
                        bool> {
  const auto new_outputs = outputs_hash.emplace(outputs).second;
  const auto new_coverage = trace_hash.emplace(trace).second;
  if (new_outputs || new_coverage) {
    std::string name = "diff_";
    std::unordered_set<std::uint64_t> unique;
    for (auto v : outputs) {
      unique.insert(v);
      utils::toStringADL(name, v);
      name += '_';
    }
    if (unique.size() >= 2u) {
      exec_result.name = std::move(name);
      libfuzzer::corpus::AddToSolution(range, exec_result, path_prefix);
    }
    return true;
  }
  return false;
}

/**
 * @fn
 * statusが未知の終了理由の組み合わせの場合または一部のターゲットのカバレッジだけに新規性が見られた場合、かつ一部のターゲットだけが正常終了している場合に実行結果と入力値に名前をつけて指定されたcorpusに追加する
 *
 * Nezhaの対応箇所
 * https://github.com/nezha-dt/nezha/blob/master/Fuzzer/FuzzerLoop.cpp#L165
 *
 * @tparm Corpus corpusの型
 * @tparm Range 入力値の型
 * @param corpus このcorpusに実行結果を追加する
 * @param range この入力値を追加する
 * @param exec_result この実行結果を追加する
 * @param trace
 * 各ターゲットの実行結果がAddToCorpusでcorpusに追加されたかどうかを表すboolのrange
 * @param known_traces
 * 過去にadd_to_solutionsを呼び出した際に渡ってきた事があるtraceのset
 * @param status 各ターゲットの終了理由を並べたPUTExitReasonTypeのrange
 * @param status_hash
 * 過去にadd_to_solutionsを呼び出した際に渡ってきた事があるstatusのset
 * @param path_prefix 出力先のディレクトリ
 */
template <typename Range>
auto AddToSolution(Range &range, libfuzzer::InputInfo &exec_result,
                   const trace_t &trace, known_traces_t &trace_hash,
                   const status_t &status, known_status_t &status_hash,
                   const fs::path &path_prefix)
    -> std::enable_if_t<utils::range::is_range_of_v<Range, std::uint8_t> &&
                            utils::range::has_data_v<Range>,
                        bool> {
  const auto new_status = status_hash.emplace(status).second;
  const auto new_coverage = trace_hash.emplace(trace).second;
  if (new_status || new_coverage) {
    std::string name = "diff_";
    bool has_zero = false;
    bool has_nonzero = false;
    for (auto v : status) {
      if (v == PUTExitReasonType::FAULT_NONE)
        has_zero = true;
      else
        has_nonzero = true;
      utils::toStringADL(name, int(v));
      name += '_';
    }
    if (has_zero && has_nonzero) {
      exec_result.name = std::move(name);
      libfuzzer::corpus::AddToSolution(range, exec_result, path_prefix);
    }
    return true;
  }
  return false;
}

} // namespace fuzzuf::algorithm::nezha::executor

#endif
