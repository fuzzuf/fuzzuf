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
 * @file until_new_coverage.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_NO_NEW_COVERAGE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_NO_NEW_COVERAGE_HPP

namespace fuzzuf::algorithm::libfuzzer {
/**
 * @class NoNewCoverage
 * @brief Check if the execution result is not expected to add to corpus.
 */
struct NoNewCoverage {
  /**
   * Check if the execution result is not expected to add to corpus.
   * @tparam State libFuzzer state type.
   * @tparam InputInfo execution result type.
   * @param state libFuzzer state.
   * @param exec_result execution result.
   * @return true if the execution result doesn't satisfy requirements to add to
   * corpus.
   */
  template <typename State, typename InputInfo>
  bool operator()(const State &state, const InputInfo &exec_result) const {
    if (exec_result.added_to_corpus) return false;
    if (state.create_info.config.reduce_depth &&
        !exec_result.found_unique_features)
      return false;
    return true;
  }
};
struct NewCoverage {
  template <typename State, typename InputInfo>
  bool operator()(const State &state, const InputInfo &exec_result) const {
    if (exec_result.added_to_corpus) return true;
    if (state.create_info.config.reduce_depth &&
        !exec_result.found_unique_features)
      return true;
    return false;
  }
};
}  // namespace fuzzuf::algorithm::libfuzzer

#endif
