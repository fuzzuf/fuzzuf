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
 * @file bswap.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_BSWAP_HPP
#define FUZZUF_INCLUDE_UTILS_BSWAP_HPP
#include <cstdint>
#include <type_traits>
namespace fuzzuf::utils {

/**
 * @class bswap
 * @brief swap byte ordering of the unsigned integer value
 * @tparam T Unsigned integer type
 */
template <typename T>
struct bswap {};
template <>
struct bswap<std::uint8_t> {
  std::uint8_t operator()(std::uint8_t v) const { return v; }
};
template <>
struct bswap<std::uint16_t> {
  std::uint16_t operator()(std::uint16_t v) const {
#ifdef __GNUC__
    return __builtin_bswap16(v);
#else
    return ((((v) >> 8) & 0xffu) | (((v)&0xffu) << 8));
#endif
  }
};
template <>
struct bswap<std::uint32_t> {
  std::uint32_t operator()(std::uint32_t v) const {
#ifdef __GNUC__
    return __builtin_bswap32(v);
#else
    return ((((v)&0xff000000u) >> 24) | (((v)&0x00ff0000u) >> 8) |
            (((v)&0x0000ff00u) << 8) | (((v)&0x000000ffu) << 24));
#endif
  }
};
template <>
struct bswap<std::uint64_t> {
  std::uint64_t operator()(std::uint64_t v) const {
#ifdef __GNUC__
    return __builtin_bswap64(v);
#else
    return ((((x)&0xff00000000000000ull) >> 56) |
            (((x)&0x00ff000000000000ull) >> 40) |
            (((x)&0x0000ff0000000000ull) >> 24) |
            (((x)&0x000000ff00000000ull) >> 8) |
            (((x)&0x00000000ff000000ull) << 8) |
            (((x)&0x0000000000ff0000ull) << 24) |
            (((x)&0x000000000000ff00ull) << 40) |
            (((x)&0x00000000000000ffull) << 56));
#endif
  }
};

/**
 * @class not_swap
 * @brief do nothing to the unsigned integer value
 * @tparam T Unsigned integer type
 */
template <typename T, typename Enable = void>
struct not_swap {};

template <typename T>
struct not_swap<T, std::enable_if_t<std::is_integral_v<T>>> {
  T operator()(T v) const { return v; }
};

#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == 1234
/**
 * @class htole
 * @brief Convert system byte order value to little endian
 * @tparam T Unsigned integer type
 */
template <typename T>
using htole = bswap<T>;

/**
 * @class htobe
 * @brief Convert system byte order value to big endian
 * @tparam T Unsigned integer type
 */
template <typename T>
using htobe = not_swap<T>;

/**
 * @class letoh
 * @brief Convert little endian value to system byte order
 * @tparam T Unsigned integer type
 */
template <typename T>
using letoh = bswap<T>;

/**
 * @class betoh
 * @brief Convert big endian value to system byte order
 * @tparam T Unsigned integer type
 */
template <typename T>
using betoh = not_swap<T>;

#elif __BYTE_ORDER__ == 4321
/**
 * @class htole
 * @brief Convert system byte order value to little endian
 * @tparam T Unsigned integer type
 */
template <typename T>
using htole = not_swap<T>;

/**
 * @class htobe
 * @brief Convert system byte order value to big endian
 * @tparam T Unsigned integer type
 */
template <typename T>
using htobe = bswap<T>;

/**
 * @class letoh
 * @brief Convert little endian value to system byte order
 * @tparam T Unsigned integer type
 */
template <typename T>
using letoh = not_swap<T>;

/**
 * @class betoh
 * @brief Convert big endian value to system byte order
 * @tparam T Unsigned integer type
 */
template <typename T>
using betoh = bswap<T>;

#endif
#endif

}  // namespace fuzzuf::utils
#endif
