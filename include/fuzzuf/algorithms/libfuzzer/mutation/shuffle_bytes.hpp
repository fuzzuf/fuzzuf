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
 * @file shuffle_bytes.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_SHUFFLE_BYTES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_SHUFFLE_BYTES_HPP
#include <cassert>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * apply std::shuffle to the data
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L93
 *
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @param rng Random number generator
 * @param data Value to modify
 * @param max_size Max length of value
 * @return length of post modification value
 */
template <typename RNG, typename Range>
auto ShuffleBytes(RNG &rng, Range &data, std::size_t max_size,
                  MutationHistory &history)
    -> std::enable_if_t<utils::range::is_range_of_v<Range, std::uint8_t>,
                        std::size_t> {
  const std::size_t size = utils::range::rangeSize(data);
  if (size > max_size || size == 0u) return 0u;
  const std::size_t shuffle_amount =
      random_value(rng, std::min(size, std::size_t(8u))) + 1u;
  const std::size_t shuffle_start = random_value(rng, size - shuffle_amount);
  assert(shuffle_start + shuffle_amount <= size);
  std::shuffle(std::next(data.begin(), shuffle_start),
               std::next(data.begin(), shuffle_start + shuffle_amount), rng);
  static const char name[] = "ShuffleBytes";
  history.push_back(MutationHistoryEntry{name});
  return utils::range::rangeSize(data);
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
