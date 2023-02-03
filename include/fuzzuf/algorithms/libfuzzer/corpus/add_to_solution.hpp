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
 * @file add_to_solution.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_ADD_TO_SOLUTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_ADD_TO_SOLUTION_HPP
#include <algorithm>
#include <cassert>
#include <fstream>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/utils/sha1.hpp"

namespace fuzzuf::algorithm::libfuzzer::corpus {

/**
 * Store execution result on the persistent storage
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L208
 *
 * @tparam Range Contiguous Range of std::uint8_t
 * @tparam InputInfo Type to provide execution result
 * @param range Input value that was passed to the executor
 * @param testcase_ Execution result that was produced by the executor
 * @param path_prefix Directory to output solutions
 */
template <typename Range, typename InputInfo>
auto AddToSolution(Range &range, InputInfo &testcase_,
                   const fs::path &path_prefix)
    -> std::enable_if_t<is_input_info_v<InputInfo>> {
  assert(!utils::range::rangeEmpty(range));

  testcase_.sha1 = utils::ToSerializedSha1(range);
  testcase_.input_size = utils::range::rangeSize(range);
  if (testcase_.name.empty()) testcase_.name = testcase_.sha1;
  std::ofstream fd((path_prefix / fs::path(testcase_.name)).string(),
                   std::ios::out | std::ios::binary);
  std::copy(range.begin(), range.end(), std::ostreambuf_iterator(fd));
}

}  // namespace fuzzuf::algorithm::libfuzzer::corpus

#endif
