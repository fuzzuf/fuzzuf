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
 * @file calc_max_length.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CALC_MAX_LENGTH_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CALC_MAX_LENGTH_HPP
#include <cstddef>
#include <type_traits>
#include <utility>

#include "fuzzuf/utils/range_traits.hpp"

/**
 * Decide max input value length using initial input values.
 * If the longest initial input value is longer than ( 1 << 20 ) bytes, the max
 * input value length is ( 1 << 20 ) If the longest initial input value is
 * between 4096 bytes and ( 1 << 20 ) bytes, the max input value length is the
 * length of longest initial input value. If the longest initial input value is
 * shorter or equal to 4096 bytes, the max input value length is 4096 This value
 * is used as the default value of max input value length
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerLoop.cpp#L373
 *
 * @tparam Range Range of range that contains initial inputs as element
 * @param inputs Initial input values
 * @return max input value length
 */
namespace fuzzuf::algorithm::libfuzzer {
template <typename Range>
auto CalcMaxLength(const Range &inputs) -> std::enable_if_t<
    utils::range::is_range_v<utils::range::RangeValueT<Range>>, std::size_t> {
  constexpr std::size_t max_sane_length = 1 << 20;
  constexpr std::size_t min_default_length = 4096;
  std::size_t max = min_default_length;
  for (const auto &input : inputs)
    max = std::max(utils::range::rangeSize(input), max);
  max = std::min(max, max_sane_length);
  return max;
}
}  // namespace fuzzuf::algorithm::libfuzzer

#endif
