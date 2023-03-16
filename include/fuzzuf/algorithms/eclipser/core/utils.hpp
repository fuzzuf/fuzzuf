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
 * @file utils.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_UTILS_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_UTILS_HPP
#include <random>
#include <cstddef>
#include <vector>
#include <unordered_set>
#include <cstdint>
#include <functional>
#include <string>
#include <fuzzuf/utils/filesystem.hpp>
#include <fuzzuf/utils/type_traits/remove_cvr.hpp>
#include <fuzzuf/algorithms/eclipser/core/bigint.hpp>

namespace fuzzuf::algorithm::eclipser {
  void Log( const std::function<void(std::string &&)> &sink, const std::string &fmt );
  BigInt GetSignedMax( unsigned int i );
  BigInt GetUnsignedMax( unsigned int i );
  std::unordered_set< int > RandomSubset( std::mt19937 &rng, int n, int k );
  std::unordered_set< std::size_t > RandomSubset( std::mt19937 &rng, std::size_t n, std::size_t k );
  std::vector< BigInt > SampleInt( BigInt min, BigInt max, std::int32_t n );
  void AssertFileExists( const std::function<void(std::string &&)> &sink, const fs::path &file );
  void WriteFile(
    const std::function<void(std::string &&)> &sink,
    const fs::path &file,
    const std::vector< std::byte > &content
  );
  void RemoveFile(
    const fs::path &file
  );
  template< typename T, typename I >
  std::vector< std::vector< utils::type_traits::RemoveCvrT< decltype( *std::declval< I >() ) > > >
  Combination(
    T n,
    const I &lst_begin,
    const I &lst_end
  ) {
    using U = utils::type_traits::RemoveCvrT< decltype( *std::declval< I >() ) >;
    if( n == T( 0 ) ) {
      return std::vector< std::vector< U > >{ {} };
    }
    if( lst_begin == lst_end ) {
      return std::vector< std::vector< U > >{};
    }
    const auto temp = Combination(
      n - T( 1 ),
      std::next( lst_begin ),
      lst_end
    );
    const auto &x = *lst_begin;
    std::vector< std::vector< U > > with_x;
    with_x.reserve( temp.size() );
    std::transform(
      temp.begin(),
      temp.end(),
      std::back_inserter( with_x ),
      [&x]( const auto &l ) {
        std::vector< U > temp;
        temp.reserve( l.size() + 1u );
        temp.push_back( x );
        temp.insert( temp.end(), l.begin(), l.end() );
        return temp;
      }
    );
    const auto with_out_x = Combination(
      n,
      std::next( lst_begin ),
      lst_end
    );
    with_x.insert(
      with_x.end(),
      with_out_x.begin(),
      with_out_x.end()
    );
    return with_x;
  }
  template< typename T, typename U >
  std::vector< std::vector< U > >
  Combination(
    T n,
    const std::vector< U > &lst
  ) {
    return Combination( n, lst.begin(), lst.end() );
  }
  template< typename I >
  auto SplitList( std::size_t n, const I &begin, const I &end ) {
    using result_type = std::vector<
      utils::type_traits::RemoveCvrT< decltype( *std::declval< I >() ) >
    >;
    return std::make_pair(
      result_type( begin, std::next( begin, std::min( n, std::size_t( std::distance( begin, end ) ) ) ) ),
      result_type( std::next( begin, std::min( n, std::size_t( std::distance( begin, end ) ) ) ), end )
    );
  }
  template< typename T >
  std::pair< T, T >
  SplitList( std::size_t n, const T &lst ) {
    return std::make_pair(
      T( lst.begin(), std::next( lst.begin(), std::min( n, lst.size() ) ) ),
      T( std::next( lst.begin(), std::min( n, lst.size() ) ), lst.end() )
    );
  }
}

#endif
