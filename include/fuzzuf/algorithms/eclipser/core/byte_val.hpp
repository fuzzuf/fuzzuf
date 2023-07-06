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

ByteVal NewByteVal( std::byte v );
std::byte GetConcreteByte( ByteVal b );
bool IsFixed( ByteVal b );
bool IsUnfixed( ByteVal b );
bool IsSampledByte( ByteVal b );
bool IsConstrained( ByteVal b );
bool IsNullByte( ByteVal b );
std::string ToString( ByteVal b );
std::tuple< std::byte, std::byte > GetMinMax( ByteVal b, InputSource input_src );
void to_json( nlohmann::json &dest, const ByteVal &src );
void from_json( const nlohmann::json &src, ByteVal &dest );

}

#endif

