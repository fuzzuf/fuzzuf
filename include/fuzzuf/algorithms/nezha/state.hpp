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
 * @file state.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_STATE_HPP
#include <boost/functional/hash.hpp>
#include <unordered_set>

#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/range_traits.hpp"

namespace fuzzuf::algorithm::nezha {

/**
 * @class output_equal_to
 * @brief callable object to check if two ranges are same
 */
struct output_equal_to {
  /**
   * Return true if two ranges are same
   * @tparam R1 Type of first range
   * @tparam R2 Type of second range
   * @param r1 First range
   * @param r2 Second range
   * @return true on same, Otherwise false.
   */
  template <typename R1, typename R2>
  bool operator()(const R1 &r1, const R2 &r2) const {
    return std::equal(r1.begin(), r1.end(), r2.begin(), r2.end());
  }
};

/**
 * @class output_hash
 * @brief callable object to calculate hash value of vector
 */
struct output_hash {
  /**
   * calculate hash value of vector
   * The implementation simply uses Boost.Hash
   * @tparam R1 Type of range
   * @param r1 Range
   * @return hash value
   */
  template <typename R1>
  std::size_t operator()(const R1 &r1) const {
    return boost::hash<R1>()(r1);
  }
};

// Vector to store bools which indicate the execution result of each targets had
// been added to corpus or not
using trace_t = std::vector<bool>;
// unordered set to check if a trace_t value is novel
using known_traces_t =
    std::unordered_set<trace_t, output_hash, output_equal_to>;

// Vector to store status code of each execution
using status_t = std::vector<feedback::PUTExitReasonType>;
// unordered set to check if a status_t value is novel
using known_status_t =
    std::unordered_set<status_t, output_hash, output_equal_to>;

// Vector to store hash value of standard output produced by each target
using outputs_t = std::vector<std::size_t>;
// unordered set to check if a outputs_t value is novel
using known_outputs_t =
    std::unordered_set<outputs_t, output_hash, output_equal_to>;

}  // namespace fuzzuf::algorithm::nezha

#endif
