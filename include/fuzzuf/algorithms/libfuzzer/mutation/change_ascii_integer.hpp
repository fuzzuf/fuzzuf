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
 * @file change_ascii_integer.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_CHANGE_ASCII_INTEGER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_CHANGE_ASCII_INTEGER_HPP
#include <cassert>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * Detect sequence of '0' to '9' characters and parse it as integer value, then
 * apply one of following operation and serialize modified value to original
 * position.
 * *  increment
 * *  decrement
 * *  multiply by two
 * *  divide by two
 * *  replace by random value
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L349
 *
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @param rng Random number generator
 * @param data Value to modify
 * @param max_size Max length of value
 * @return length of post modification value
 */
template <typename RNG, typename Range>
auto ChangeASCIIInteger(RNG &rng, Range &data, size_t max_size,
                        MutationHistory &history)
    -> std::enable_if_t<utils::range::is_range_of_v<Range, std::uint8_t>,
                        size_t> {
  const size_t size = utils::range::rangeSize(data);
  if (size > max_size) return 0u;
  const size_t b = random_value(rng, size);
  const auto begin = std::find_if(std::next(data.begin(), b), data.end(),
                                  [](auto v) { return isdigit(v); });
  if (begin == data.end()) return 0u;
  const auto end =
      std::find_if(begin, data.end(), [](auto v) { return !isdigit(v); });
  assert(begin < end);
  // now we have digits in [B, E).
  // strtol and friends don't accept non-zero-teminated data, parse it manually.
  uint64_t value = *begin - '0';
  for (auto i = std::next(begin); i < end; ++i) value = value * 10 + *i - '0';
  // Mutate the integer value.
  switch (random_value(rng, 5)) {
    case 0:
      value++;
      break;
    case 1:
      value--;
      break;
    case 2:
      value /= 2u;
      break;
    case 3:
      value *= 2u;
      break;
    case 4:
      value = random_value(rng, (value * value));
      break;
    default:
      assert(0);
  }
  // Just replace the bytes with the new ones, don't bother moving bytes.
  for (auto i = std::make_reverse_iterator(end);
       i < std::make_reverse_iterator(begin); ++i) {
    *i = (value % 10u) + '0';
    value /= 10u;
  }
  static const char name[] = "ChangeASCIIInt";
  history.push_back(MutationHistoryEntry{name});
  return utils::range::rangeSize(data);
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
