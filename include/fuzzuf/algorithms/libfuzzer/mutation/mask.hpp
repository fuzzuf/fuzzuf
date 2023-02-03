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
 * @file mask.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_MASK_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_MASK_HPP
#include <cassert>
#include <iterator>
#include <type_traits>
#include <vector>

#include "fuzzuf/utils/filtered_range.hpp"
#include "fuzzuf/utils/nth_range.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/zip_range.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * Copy elements of data which corresponding mask value is not zero to dest
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L545
 *
 * @tparam R1 Range of original value
 * @tparam Mask Range of mask value
 * @tparam R2 Container to output masked value
 * @param data Original value
 * @param mask Mask value
 * @param dest Output container
 * @return length of post modification value
 */
template <typename R1, typename Mask_, typename R2>
auto Mask(const R1 &data, const Mask_ &mask, R2 &dest) -> std::enable_if_t<
    utils::range::is_range_of_v<R1, std::uint8_t> &&
        std::is_integral_v<utils::range::RangeValueT<Mask_>> &&
        utils::range::is_range_of_v<R2, std::uint8_t>,
    void> {
  const size_t masked_size =
      std::min(utils::range::rangeSize(data), utils::range::rangeSize(mask));
  // * Copy the worthy bytes into a temporary array T
  // * Mutate T
  // * Copy T back.
  // This is totally unoptimized.
  dest.clear();
  dest.reserve(masked_size);
  utils::range::copy(utils::range::zip(mask, data) |
                         utils::range::adaptor::filtered(
                             [](const auto v) { return std::get<0>(v); }) |
                         utils::range::adaptor::nth<1u>,
                     std::back_inserter(dest));
}

/**
 * Update elements in data which corresponding mask value is non-zero by values
 * from src
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L545
 *
 * @tparam R1 Range of masked value
 * @tparam Mask Range of mask value
 * @tparam R2 Container to output
 * @param data Masked value
 * @param mask Mask value
 * @param dest Output container
 * @return length of post modification value
 */
template <typename R1, typename Mask, typename R2>
auto Unmask(const R1 &src, const Mask &mask, R2 &data) -> std::enable_if_t<
    utils::range::is_range_of_v<R1, std::uint8_t> &&
        std::is_integral_v<utils::range::RangeValueT<Mask>> &&
        utils::range::is_range_of_v<R2, std::uint8_t>,
    void> {
  assert(utils::range::rangeSize(mask) <= utils::range::rangeSize(data));
  auto mi = mask.begin();
  auto si = src.begin();
  auto di = data.begin();
  std::vector<std::uint8_t> temp;
  temp.reserve(data.size());
  for (; mi != mask.end() && si != src.end() && di != data.end(); ++mi, ++di) {
    if (*mi) {
      temp.push_back(*si);
      ++si;
    } else
      temp.push_back(*di);
  }
  for (; mi != mask.end() && di != data.end(); ++mi, ++di) {
    if (!*mi) temp.push_back(*di);
  }
  for (; di != data.end(); ++di) {
    temp.push_back(*di);
  }
  utils::range::assign(temp, data);
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
