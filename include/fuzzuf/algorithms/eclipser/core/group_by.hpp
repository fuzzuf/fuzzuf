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
 * @file group_by.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_GROUP_BY_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_GROUP_BY_HPP
#include <cstddef>
#include <variant>
#include <nlohmann/json_fwd.hpp>
#include <boost/multiprecision/cpp_int.hpp>

namespace fuzzuf::algorithm::eclipser {

template< typename F, typename T >
auto GroupBy( const F &f, const T &src ) {
  using KeyType = utils::type_traits::RemoveCvrT< decltype( f( *src.begin() ) ) >;
  std::unordered_map< KeyType, T > temp;
  for( auto &v: src ) {
    auto key = f( v );
    const auto existing = temp.find( key );
    if( existing == temp.end() ) {
      temp.emplace( std::move( key ), T{{ v }} );
    }
    else {
      existing->second.push_back( v );
    }
  }
  return temp;
}

}

#endif

