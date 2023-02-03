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
 * @file for_each_non_zero_byte.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_FOR_EACH_NON_ZERO_BYTE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_FOR_EACH_NON_ZERO_BYTE_HPP
#include <boost/range/iterator_range.hpp>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

#include "fuzzuf/utils/bswap.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/void_t.hpp"
namespace fuzzuf::algorithm::libfuzzer::feature {

/**
 * Call cb for each non-zero bytes in the range.
 * For pointer
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerTracePC.h#L184
 *
 * @tparam Range Range compliant type of input values
 * @tparam Integer Type of first_feature
 * @tparam Callback Callable with three integer arguments for first_feature,
 * distance from begin() to current element and value of current element.
 * @param data Call cb for each non-zero elements of this range
 * @param first_feature This value is always passed to the first argument of cb
 * @param cb Callable with three integer arguments for first_feature, distance
 * from begin() to current element and value of current element.
 * @return length of data
 */
template <typename Range, typename Integer, typename Callback>
auto ForEachNonZeroByte(const Range &data, Integer first_feature, Callback cb)
    -> std::enable_if_t<
        std::is_pointer_v<utils::range::RangeIteratorT<Range>> &&
            utils::range::is_range_of_v<Range, std::uint8_t> &&
            std::is_integral_v<Integer> &&
            std::is_void_v<utils::void_t<decltype(std::declval<Callback>()(
                Integer(0), Integer(0), std::uint8_t(0)))>>,
        size_t> {
  constexpr std::size_t step = sizeof(std::uintptr_t) / sizeof(std::uint8_t);
  constexpr std::size_t step_mask = step - 1u;
  auto iter = data.begin();
  auto end = data.end();
  // Iterate by 1 byte until either the alignment boundary or the end.
  for (; reinterpret_cast<std::uintptr_t>(iter) & step_mask && iter < end;
       ++iter) {
    if (auto v = *iter)
      cb(first_feature, Integer(std::distance(data.begin(), iter)), v);
  }
  // Iterate by Step bytes at a time.
  for (; iter + step <= end; iter += step)
    if (std::uintptr_t bundle = *reinterpret_cast<const uintptr_t *>(iter)) {
      bundle = utils::htole<std::uintptr_t>()(bundle);
      for (std::size_t i = 0u; i < step; ++i, bundle >>= 8) {
        if (uint8_t v = bundle & 0xFFu)
          cb(first_feature, Integer(std::distance(data.begin(), iter) + i), v);
      }
    }

  // Iterate by 1 byte until the end.
  for (; iter < end; ++iter) {
    if (std::uint8_t v = *iter)
      cb(first_feature, Integer(std::distance(data.begin(), iter)), v);
  }
  return std::distance(data.begin(), end);
}

/**
 * Call cb for each non-zero bytes in the range.
 * For non-pointer iterator
 *
 * @tparam Range Range compliant type of input values
 * @tparam Integer Type of first_feature
 * @tparam Callback Callable with three integer arguments for first_feature,
 * distance from begin() to current element and value of current element.
 * @param data Call cb for each non-zero elements of this range
 * @param first_feature This value is always passed to the first argument of cb
 * @param cb Callable with three integer arguments for first_feature, distance
 * from begin() to current element and value of current element.
 * @return length of data
 */
template <typename Range, typename Integer, typename Callback>
auto ForEachNonZeroByte(const Range &data, Integer first_feature, Callback cb)
    -> std::enable_if_t<
        !std::is_pointer_v<utils::range::RangeIteratorT<Range>> &&
            utils::range::is_range_of_v<Range, std::uint8_t> &&
            std::is_integral_v<Integer> &&
            std::is_void_v<utils::void_t<decltype(std::declval<Callback>()(
                Integer(0), Integer(0), std::uint8_t(0)))>>,
        size_t> {
  std::size_t index = 0u;
  // Iterate by 1 byte until the end.
  for (auto v : data) {
    if (v) cb(first_feature, Integer(index), v);
    ++index;
  }
  return std::distance(data.begin(), data.end());
}

}  // namespace fuzzuf::algorithm::libfuzzer::feature

#endif
