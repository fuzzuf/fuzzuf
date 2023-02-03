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
 * @file erase_bytes.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_ERASE_BYTES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_ERASE_BYTES_HPP
#include <cassert>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * Remove random range of data
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L104
 *
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @param rng Random number generator
 * @param data Value to modify
 * @param max_size Max length of value
 * @return length of post modification value
 */
template <typename RNG, typename Range>
auto EraseBytes(RNG &rng, Range &data, std::size_t, MutationHistory &history)
    -> std::enable_if_t<
        // Rangeはメンバ関数eraseを持っている
        utils::range::has_erase_v<Range>, std::size_t> {
  const std::size_t size = utils::range::rangeSize(data);
  if (size <= 1u) return 0u;
  const std::size_t n = random_value(rng, size / 2u) + 1u;
  assert(n < size);
  const std::size_t index = random_value(rng, size - n + 1u);
  // Erase Data[Idx:Idx+N].
  data.erase(std::next(data.begin(), index),
             std::next(data.begin(), index + n));
  // Printf("Erase: %zd %zd => %zd; Idx %zd\n", N, Size, Size - N, Idx);
  static const char name[] = "EraseBytes";
  history.push_back(MutationHistoryEntry{name});
  return utils::range::rangeSize(data);
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
