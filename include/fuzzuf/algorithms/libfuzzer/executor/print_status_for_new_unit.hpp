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
 * @file print_status_for_new_unit.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTE_PRINT_STATUS_FOR_NEW_UNIT_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTE_PRINT_STATUS_FOR_NEW_UNIT_HPP
#include <chrono>
#include <functional>
#include <string>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/to_hex.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

namespace fuzzuf::algorithm::libfuzzer::executor {

/**
 * Print execution result and fuzzer state as in the format similar to
 * original implementation.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerLoop.cpp#L648
 *
 * @tparam Range Contiguous Range of std::uint8_t to pass input
 * @tparam InputInfo Type to provide execution result
 * @tparam DictEntries Range of pointer to dictionary entries
 * @param range Input value that was passed to the executor
 * @param exec_result Execution result that was produced by the executor
 * @param max_size Miximum length of input value
 * @param history Range of strings that indicate which mutator had been used to
 * generate current input
 * @param dict_entries Range of pointer to dictionary entries which had been
 * used to generate current input
 * @param cycle Current cycle of global fuzzer loop
 * @param begin_date Datetime that the fuzzing started
 * @param verbosity If 0, minimum informatios are displayed. If 1, minimum
 * informations, input length, limited number of elements of history and
 * dict_entries and input value( only if the input value is short enough ) are
 * displayed. If 2 or higher, minimum informations, input length, all elements
 * of history and dict_entries and input value( only if the input value is short
 * enough ) are displayed.
 * @param max_mutations_to_print If verbosity is 1, this number of elements on
 * the head of history and dict_entries are displayed. Otherwise, the value is
 * ignored.
 * @param max_unit_size_to_print If the input is shorter or equal to this value
 * and verbosity is 1 or higher, the input value is displayed.
 * @param sink Callback function with one string argument to display message
 */
template <typename Range, typename InputInfo, typename DictEntries>
auto PrintStatusForNewUnit(
    Range &range, const InputInfo &exec_result, std::size_t max_size,
    const MutationHistory &history, const DictEntries &dict_entries,
    std::size_t cycle, const std::chrono::system_clock::time_point &begin_date,
    unsigned int verbosity, std::size_t max_mutations_to_print,
    std::size_t max_unit_size_to_print,
    const std::function<void(std::string &&)> &sink)
    -> std::enable_if_t<is_input_info_v<InputInfo> &&
                        utils::range::is_range_of_v<Range, std::uint8_t> &&
                        utils::range::has_data_v<Range>> {
  std::string message = "#";
  utils::toString(message, cycle);
  message += exec_result.reduced ? " REDUCE" : " NEW   ";
  auto total_coverage_size = 0u;
  message += " cov: ";
  // FIXME
  utils::toString(message, total_coverage_size);
  message += " ft: ";
  utils::toString(message, exec_result.features_count);
  message += " corp: ";
  const auto active_input_count = std::count_if(
      range.begin(), range.end(), [](const auto &i) { return bool(i); });
  utils::toString(message, active_input_count);
  message += "/";
  if (range.size() < (std::size_t(1) << 14)) {
    utils::toString(message, range.size());
    message += "b";
  }
  if (range.size() < (std::size_t(1) << 24)) {
    utils::toString(message, range.size() >> 10);
    message += "Kb";
  } else {
    utils::toString(message, range.size() >> 20);
    message += "Mb";
  }
  message += " lim: ";
  utils::toString(message, max_size);
  message += " exec/s: ";
  const auto current_date = std::chrono::system_clock::now();
  const auto elapsed_time_in_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(current_date -
                                                       begin_date)
          .count();
  utils::toString(
      message, elapsed_time_in_seconds ? cycle / elapsed_time_in_seconds : 0u);

  if (verbosity) {
    message += " L: ";
    utils::toString(message, utils::range::rangeSize(range));
    message += "/";
    utils::toString(message, max_size);
    message += " MS: ";
    utils::toString(message, history.size());
    message += " ";
    const bool verbose = verbosity >= 2u;
    {
      const std::size_t entries_to_print =
          verbose ? history.size()
                  : std::min(max_mutations_to_print, history.size());
      std::for_each(history.begin(),
                    std::next(history.begin(), entries_to_print),
                    [&message](const auto &v) {
                      message += v.name;
                      message += "-";
                    });
    }
    if (!dict_entries.empty()) {
      message += " DE: ";
      const std::size_t entries_to_print =
          verbose ? dict_entries.size()
                  : std::min(max_mutations_to_print, dict_entries.size());
      std::for_each(dict_entries.begin(),
                    std::next(dict_entries.begin(), entries_to_print),
                    [&message](const auto &v) {
                      message += "\"";
                      const auto &word = v->get();
                      message += std::string(word.begin(), word.end());
                      message += "\"-";
                    });
    }
    if (max_unit_size_to_print) {
      message += "; base unit: ";
      message += exec_result.sha1;
      message += " ";
      const std::size_t unit_size = utils::range::rangeSize(range);
      if (unit_size <= max_unit_size_to_print) {
        std::vector<std::uint8_t> contiguous(range.begin(), range.end());
        utils::toHex(message, contiguous);
      }
    }
  }
  message += "\n";
  sink(std::move(message));
}

}  // namespace fuzzuf::algorithm::libfuzzer::executor

#endif
