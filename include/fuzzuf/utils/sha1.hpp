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
 * @file sha1.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_SHA1_HPP
#define FUZZUF_INCLUDE_UTILS_SHA1_HPP
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::utils {

namespace detail {
auto ToSerializedSha1Contiguous(const std::vector<std::uint8_t> &range)
    -> std::string;
}

/**
 * Calculate sha1 hash of the data in the range that is not std::vector<
 * std::uint8_t >, then serialize the hash in hexadecimal string. This format is
 * typically used to determine the name of input in libFuzzer.
 * @tparam Range C++17 range concept compliant range with std::uint8_t as
 * value_type excluding std::vector< std::uint8_t >
 * @param range The range containing data
 * @return hexadecimal string
 */
template <typename Range>
auto ToSerializedSha1(const Range &range)
    -> std::enable_if_t<!std::is_same_v<utils::type_traits::RemoveCvrT<Range>,
                                        std::vector<std::uint8_t>>,
                        std::string> {
  std::vector<std::uint8_t> contiguous(range.begin(), range.end());
  return detail::ToSerializedSha1Contiguous(contiguous);
}
/**
 * Calculate sha1 hash of the data in std::vector< std::uint8_t >, then
 * serialize the hash in hexadecimal string. This format is typically used to
 * determine the name of input in libFuzzer.
 * @tparam Range The range type that must be std::vector< std::uint8_t >
 * @param range The range containing data
 * @return hexadecimal string
 */
template <typename Range>
auto ToSerializedSha1(const Range &range)
    -> std::enable_if_t<std::is_same_v<utils::type_traits::RemoveCvrT<Range>,
                                       std::vector<std::uint8_t>>,
                        std::string> {
  return detail::ToSerializedSha1Contiguous(range);
}

}  // namespace fuzzuf::utils
#endif
