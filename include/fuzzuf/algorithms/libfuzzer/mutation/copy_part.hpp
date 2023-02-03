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
 * @file copy_part.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_COPY_PART_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_COPY_PART_HPP
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/mutation/utils.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * Copy random range of data to random range of data, or insert random range of
 * data to random position.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L338
 *
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @param rng Random number generator
 * @param data Value to modify
 * @param max_size Max length of value
 * @return length of post modification value
 */
template <typename RNG, typename Range>
auto CopyPart(RNG &rng, Range &data, std::size_t max_size,
              MutationHistory &history)
    -> std::enable_if_t<
        // Rangeは整数のrangeである
        utils::range::is_range_v<Range>, std::size_t> {
  const std::size_t size = utils::range::rangeSize(data);
  if (size > max_size || size == 0) return 0;
  // If Size == MaxSize, `InsertPartOf(...)` will
  // fail so there's no point using it in this case.
  if (size == max_size || random_value<bool>(rng))
    detail::CopyPartOf(rng, data, data, true);
  else
    detail::InsertPartOf(rng, data, data, true, max_size);
  static const char name[] = "CopyPart";
  history.push_back(MutationHistoryEntry{name});
  return utils::range::rangeSize(data);
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
