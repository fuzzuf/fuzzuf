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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_VERSION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_VERSION_HPP

namespace fuzzuf::algorithm::libfuzzer {

// llvmのバージョンを32bit整数にエンコードした物
using Version = std::uint32_t;

// llvmのバージョンのtripleを32bitの整数にする
template <typename T>
constexpr auto MakeVersion(T major, T minor, T patch)
    -> std::enable_if_t<std::is_convertible_v<T, std::uint32_t>, Version> {
  return Version((std::uint32_t(major) << 16u) | (std::uint32_t(minor) << 16u) |
                 std::uint32_t(patch));
}

namespace version {
// Nezhaが実装された時点のllvmのバージョン
constexpr Version nezha = MakeVersion(4u, 0u, 1u);
} // namespace version

} // namespace fuzzuf::algorithm::libfuzzer

#endif
