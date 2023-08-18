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
 * @file bytes_utils.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_BYTES_UTILS_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_BYTES_UTILS_HPP

#include <vector>
#include <cstddef>
#include <fuzzuf/algorithms/eclipser/core/bigint.hpp>

namespace fuzzuf::algorithm::eclipser {

enum class Endian {
  LE,
  BE
};

/**
 * Serialize Endian into JSON
 * @param dest reference to the JSON
 * @param src Endian
 */
void to_json( nlohmann::json&, Endian );
/**
 * Deserialize Endian from JSON
 * @param src reference to the JSON
 * @param dest Endian
 */
void from_json( const nlohmann::json&, Endian& );

/**
 * Convert BigInt value to byte sequence
 * @param endian endianess
 * @param sequence length in bytes
 * @param value BigInt value
 * @return byte sequence
 */
std::vector< std::byte >
BigIntToBytes( Endian endian, std::size_t size, BigInt value );
/**
 * Convert byte sequence to BigInt value
 * @param endian endianess
 * @param bytes byte sequence
 * @return BigInt value
 */
BigInt BytesToBigInt( Endian endian, const std::vector< std::byte > &bytes );

}

#endif

