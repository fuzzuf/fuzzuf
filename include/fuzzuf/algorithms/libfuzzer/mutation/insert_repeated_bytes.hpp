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
 * @file insert_repeated_bytes.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_INSERT_REPEATED_BYTES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_INSERT_REPEATED_BYTES_HPP
#include <cassert>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * Insert random length of 0x00 or 0xff at the random position of data
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L126
 *
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @param rng Random number generator
 * @param data Value to modify
 * @param max_size Max length of value
 * @return length of post modification value
 */
template <typename RNG, typename Range>
auto InsertRepeatedBytes(RNG &rng, Range &data, size_t max_size,
                         MutationHistory &history)
    -> std::enable_if_t<
        // Rangeは整数のrangeである
        utils::range::is_integral_range_v<Range> &&
            // Rangeはメンバ関数insertを持っている
            utils::range::has_insert_value_n_v<Range>,
        size_t> {
  constexpr size_t min_bytes_to_insert = 3u;
  const size_t size = utils::range::rangeSize(data);
  if (size + min_bytes_to_insert >= max_size) return 0u;
  const size_t max_bytes_to_insert = std::min(max_size - size, size_t(128u));
  const size_t n =
      random_value(rng, max_bytes_to_insert - min_bytes_to_insert + 1) +
      min_bytes_to_insert;
  assert(size + n <= max_size && n);
  const size_t index = random_value(rng, size + 1);
  // Give preference to 0x00 and 0xff.
  using value_t = utils::range::RangeValueT<Range>;
  const value_t value = random_value<bool>(rng)
                            ? value_t(0)
                            : std::numeric_limits<value_t>::max();
  // Insert new values at Data[Idx].
  data.insert(std::next(data.begin(), index), n, value);
  static const char name[] = "InsertRepeatedBytes";
  history.push_back(MutationHistoryEntry{name});
  return utils::range::rangeSize(data);
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
