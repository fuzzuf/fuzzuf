/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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
 * @file bytes_utils.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/core/bytes_utils.hpp>

namespace fuzzuf::algorithm::eclipser {

void to_json( nlohmann::json &dest, Endian src ) {
  if( src == Endian::LE ) {
    dest = "LE";
  }
  else if( src == Endian::BE ) {
    dest = "BE";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, Endian &dest ) {
  if( src.is_string() ) {
    if( src == "LE" ) {
      dest = Endian::LE;
    }
    else if( src == "BE" ) {
      dest = Endian::BE;
    }
    else {
      dest = Endian::LE;
    }
  }
  else if( src.is_number() ) {
    dest = Endian( int( src ) );
  }
  else {
    dest = Endian::LE;
  }
}


std::vector< std::byte >
BigIntToBytes( Endian endian, std::size_t size, BigInt value ) {
  std::vector< std::byte > temp;
  temp.reserve( size );
  for( std::size_t i = 0u; i != size; ++i ) {
    temp.push_back( std::byte( std::uint8_t( value ) ) );
    value >>= 8;
  }
  if( endian == Endian::BE ) {
    std::reverse( temp.begin(), temp.end() );
  }
  return temp;
}

BigInt BytesToBigInt( Endian endian, const std::vector< std::byte > &bytes ) {
  BigInt v;
  if( endian == Endian::LE ) {
    for( auto iter = bytes.rbegin(); iter != bytes.rend(); ++iter ) {
      v <<= 8;
      v += uint32_t( *iter );
    }
  }
  else {
    for( auto iter = bytes.begin(); iter != bytes.end(); ++iter ) {
      v <<= 8;
      v += uint32_t( *iter );
    }
  }
  return v;
}

}

