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
 * @file change_binary_integer.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_CHANGE_BINARY_INTEGER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_CHANGE_BINARY_INTEGER_HPP
#include <cassert>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/mutation/utils.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * Consider random length from random offset of the data is a signed integer in
 * two complement representation, then modify the value in range of -10 to 10
 * and writeback modified value to original position. This operation may change
 * byte order at writeback. This operation may invert the sign at writeback.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L408
 *
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @param rng Random number generator
 * @param data Value to modify
 * @param max_size Max length of value
 * @return length of post modification value
 */
template <typename RNG, typename Range>
auto ChangeBinaryInteger(RNG &rng, Range &data, size_t max_size,
                         MutationHistory &history)
    -> std::enable_if_t<utils::range::is_range_of_v<Range, std::uint8_t>,
                        size_t> {
  const size_t size = utils::range::rangeSize(data);
  if (size > max_size) return 0;
  static const char name[] = "ChangeBinInt";
  history.push_back(MutationHistoryEntry{name});
  switch (random_value(rng, 4u)) {
    case 3:
      return detail::ChangeBinaryInteger<uint64_t>(rng, data);
    case 2:
      return detail::ChangeBinaryInteger<uint32_t>(rng, data);
    case 1:
      return detail::ChangeBinaryInteger<uint16_t>(rng, data);
    case 0:
      return detail::ChangeBinaryInteger<uint8_t>(rng, data);
    default:
      assert(0);
  }
  return 0;
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
