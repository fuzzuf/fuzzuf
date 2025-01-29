/*
 * fuzzuf
 * Copyright (C) 2021-2025 Ricerca Security
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
 * @file get_aligned_addr.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/get_afl_map_size.hpp"

#include <cstdlib>
#include <cstring>
#include <algorithm>
#if __GNUC__ >= 8
#include <charconv>
#else
#include <boost/spirit/include/qi.hpp>
#endif

namespace fuzzuf::utils {
std::size_t get_afl_map_size( std::size_t default_size ) {
  const auto afl_map_size_maybe = std::getenv( "AFL_MAP_SIZE" );
  std::size_t afl_map_size = default_size;
  if( afl_map_size_maybe ) {
    const std::size_t len = std::strlen( afl_map_size_maybe );
    std::size_t temp;
#if __GNUC__ >= 8
    if( std::from_chars( afl_map_size_maybe, afl_map_size_maybe + len, temp ).ec == std::errc{} ) {
#else
    namespace qi = boost::spirit::qi;
    if( qi::parse( afl_map_size_maybe, afl_map_size_maybe + len, qi::ulong_long, temp ) ) {
#endif
      afl_map_size = std::max( temp, afl_map_size );
    }
  }
  return afl_map_size;
}
}
