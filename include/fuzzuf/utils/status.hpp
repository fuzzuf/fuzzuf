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
 * @file status.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_STATUS_HPP
#define FUZZUF_INCLUDE_UTILS_STATUS_HPP
#include <iostream>

#include "fuzzuf/utils/enum_cast.hpp"
namespace fuzzuf::utils {
/**
 * This enum is intended to express result and roughly reason of failure instead
 * to just result. Since exception doesn't sit well on some programming models
 * like asynchronous I/O, this enum is useful to express the result. Everything
 * that is considered as status appearing in the product  should be contained in
 * the enum.
 */
enum class status_t {
  UNKNOWN,      // status is unknown or not determined yet.
  OK,           // the request was completed successfully
  BAD_REQUEST,  // the request was rejected due to invalid parameter
  CONFLICT,     // the request was rejected due to other request concurrently
                // proceeded has changed the situation
  DISCONNECTED  // the request was rejected due to remote connection is closed
};

// Meta function to check if the type has each value of status type
// Each metafunctions are placed under namespace detail::enum_cast::status
FUZZUF_ENUM_CAST_CHECK(status, UNKNOWN)
FUZZUF_ENUM_CAST_CHECK(status, OK)
FUZZUF_ENUM_CAST_CHECK(status, BAD_REQUEST)
FUZZUF_ENUM_CAST_CHECK(status, CONFLICT)
FUZZUF_ENUM_CAST_CHECK(status, DISCONNECTED)

/**
 * Define statusCast< typename T, bool strict = true, typename U >( U value )
 * This cast preserve enum label name instead the integral value.
 * For example, in the case type T with OK = 2 and type U with OK=3 are
 * available, statusCast< U >( T::OK ) results U::OK == 3. usage 1: statusCast<
 * some sort of enum type >( value of some sort of enum type ) Convert value of
 * enum type U to value of enum type T T must enum type with UNKNOWN as its
 * element U must enum type type of return value is T Conversion bases the name
 * instead the value (U::HOGE will converted to T::HOGE if available) If T
 * doesn't have corresponding value, the bihaviour depends on the value of
 * strict. if true(default), such conversion causes static_assert, then
 * compilation fails. Otherwise, statusCast returns T::UNKNOWN for values that
 * is not available in T usage 2: statusCast< std::string >( some sort of enum
 * type ) Stringize value of enum type U U must enum type Return value is
 * stringized label of enum (U::HOGE will converted to "HOGE") strict is ignored
 * usage 3:
 *   statusCast< some sort of enum type >( value of std::string )
 *   Convert enum label name in string to corresponding enum value
 *   T must enum type with UNKNOWN as its element
 *   U must convertible to std::string
 *   type of return value is T
 *   ("HOGE" will converted to T::HOGE)
 *   If no enum values match to the string, the return value is T::UNKNOWN
 *   Since contents of string is determined in runtime, strict is ignored
 */
FUZZUF_ENUM_CAST_BEGIN(status, UNKNOWN){
    FUZZUF_ENUM_CAST_CONVERT(UNKNOWN) FUZZUF_ENUM_CAST_CONVERT(OK)
        FUZZUF_ENUM_CAST_CONVERT(BAD_REQUEST) FUZZUF_ENUM_CAST_CONVERT(CONFLICT)
            FUZZUF_ENUM_CAST_CONVERT(DISCONNECTED)} FUZZUF_ENUM_CAST_END

    // status_t can be passed to output stream
    // This is intended to use for debug and unit test outputs
    template <typename Traits>
    std::basic_ostream<char, Traits> &operator<<(
        std::basic_ostream<char, Traits> &l, status_t r) {
  l << statusCast<std::string>(r);
  return l;
}

}  // namespace fuzzuf::utils

#endif
