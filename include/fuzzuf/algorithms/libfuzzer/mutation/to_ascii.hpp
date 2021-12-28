/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_TO_ASCII_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_TO_ASCII_HPP
#include "fuzzuf/utils/range_traits.hpp"
#include <iterator>
#include <type_traits>
namespace fuzzuf::algorithm::libfuzzer::mutator {

/*
 * @fn
 * Apply bitmask 0x7F for each elements of data and replace value to space if the masked value is not std::isspace() nor std::isprint().
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerUtil.cpp#L59
 *
 * @tparm Range range to modify
 * @param data range to modify
 * @return True if modified. Otherwise false.
 */
template <typename Range>
auto ToASCII(Range &data) -> std::enable_if_t<
    // Rangeは整数のrangeである
    utils::range::is_range_v<Range>, bool> {
  bool changed = false;
  for (auto &x : data) {
    auto new_x = x;
    new_x &= 127;
    if (!std::isspace(new_x) && !std::isprint(new_x))
      new_x = ' ';
    changed |= new_x != x;
    x = new_x;
  }
  return changed;
}

} // namespace fuzzuf::algorithm::libfuzzer::mutator

#endif
