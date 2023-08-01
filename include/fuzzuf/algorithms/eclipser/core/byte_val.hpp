/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file byte_val.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_BYTE_VAL_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_BYTE_VAL_HPP
#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>
#include <config.h>
#ifdef HAS_NLOHMANN_JSON_FWD
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>
#include <fuzzuf/utils/type_traits/remove_cvr.hpp>

namespace fuzzuf::algorithm::eclipser::byteval {

struct Fixed {
  std::byte value = std::byte( 0u );
};
struct Interval {
  std::byte low = std::byte( 0u );
  std::byte high = std::byte( 0u );
};
struct Undecided {
  std::byte value = std::byte( 0u );
};
struct Untouched {
  std::byte value = std::byte( 0u );
};
struct Sampled {
  std::byte value = std::byte( 0u );
};
using ByteVal = std::variant<
  Fixed,
  Interval,
  Undecided,
  Untouched,
  Sampled
>;

using ByteVals = std::vector< ByteVal >;

/**
 * Create ByteVal from a byte value
 * @param v value
 * @return Untouched ByteVal with value v
 */
ByteVal NewByteVal( std::byte v );
/**
 * Unwrap ByteVal and retrive the value
 * If the ByteVal is Interval, the center of the range is return.
 * @param b ByteVal
 * @return Unwrapped value
 */
std::byte GetConcreteByte( ByteVal b );
/**
 * Return true if the ByteVal is Fixed
 * @param b ByteVal
 * @return true if b is Fixed
 */
bool IsFixed( ByteVal b );
/**
 * Return true if the ByteVal is not Fixed
 * @param b ByteVal
 * @return true if b is not Fixed 
 */
bool IsUnfixed( ByteVal b );
/**
 * Return true if the ByteVal is Sampled
 * @param b ByteVal
 * @return true if b is Sampled
 */
bool IsSampledByte( ByteVal b );
/**
 * Return true if the ByteVal is Fixed or Interval
 * @param b ByteVal
 * @return true if b is Fixed or Interval
 */
bool IsConstrained( ByteVal b );
/**
 * Return true if concretized value of the ByteVal is 0
 * @param b ByteVal
 * @return true if concretized value of b is 0
 */
bool IsNullByte( ByteVal b );
/**
 * Serialize the ByteVal into string
 * @param b ByteVal
 * @return serialized string
 */
std::string ToString( ByteVal b );
/**
 * Return the value range that satisfies the ByteVal
 * @param b ByteVal
 * @return tuple of values which first value indicates minimum and second value indicates maximum
 */
std::tuple< std::byte, std::byte > GetMinMax( ByteVal b, InputSource input_src );
/**
 * Serialize ByteVal into JSON
 * @param dest reference to the JSON
 * @param src ByteVal
 */
void to_json( nlohmann::json &dest, const ByteVal &src );
/**
 * Deserialize ByteVal from JSON
 * @param src reference to the JSON
 * @param dest ByteVal
 */
void from_json( const nlohmann::json &src, ByteVal &dest );

}

#endif

