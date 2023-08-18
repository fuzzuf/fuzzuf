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
 * @file utils.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <fstream>
#include <limits>
#include <chrono>
#if __GNUC__ >= 8
#include <charconv>
#endif
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/algorithms/eclipser/core/utils.hpp>

namespace fuzzuf::algorithm::eclipser {
  namespace {
    const auto startTime = std::chrono::system_clock::now();
  }
  bool Expired(
    int timelimit
  ) {
    if( timelimit < 0 ) return false;
    const auto elapsed = std::chrono::system_clock::now() - startTime;
    const int total_sec = std::chrono::duration_cast< std::chrono::seconds >( elapsed ).count();
    return total_sec >= timelimit;
  }
  void Log( const std::function<void(std::string &&)> &sink, const std::string &fmt ) {
    const auto elapsed = std::chrono::system_clock::now() - startTime;
    const auto total_sec = std::chrono::duration_cast< std::chrono::seconds >( elapsed ).count();
    const std::array< decltype( total_sec ), 4u > c{{
      ( total_sec / 60 / 60 / 24 ) % 100,
      ( total_sec / 60 / 60 ) % 24,
      ( total_sec / 60 ) % 60,
      total_sec % 60
    }};
    std::string temp( "[00:00:00:00] " );
    for( std::size_t i = 0u; i != c.size(); ++i ) {
      if( c[ i ] ) {
#if __GNUC__ >= 8
        std::to_chars(
          std::next( temp.data(), i * 3u + ( ( c[ i ] < 10 ) ? 2u : 1u ) ),
          std::next( temp.data(), i * 3u + 4u ),
          int( c[ i ] )
        );
#else
        temp[ i * 3u + 1u ] = ( ( c[ i ] / 10 ) & 0xF ) + '0';
        temp[ i * 3u + 2u ] = ( c[ i ] % 10 ) + '0';
#endif
      }
    }
    sink( temp + fmt );
  }

  BigInt GetSignedMax( unsigned int i ) {
    switch( i ) {
      case 1u:
        return std::numeric_limits< std::int8_t >::max();
      case 2u:
        return std::numeric_limits< std::int16_t >::max();
      case 4u:
        return std::numeric_limits< std::int32_t >::max();
      case 8u:
        return std::numeric_limits< std::int64_t >::max();
      default:
        return ( BigInt( 1 ) << ( i * 8 - 1 ) ) - 1;
    };
  }
  BigInt GetUnsignedMax( unsigned int i ) {
    switch( i ) {
      case 1u:
        return std::numeric_limits< std::uint8_t >::max();
      case 2u:
        return std::numeric_limits< std::uint16_t >::max();
      case 4u:
        return std::numeric_limits< std::uint32_t >::max();
      case 8u:
        return std::numeric_limits< std::uint64_t >::max();
      default:
        return ( BigInt( 1 ) << ( i * 8 ) ) - 1u;
    };
  }
  std::unordered_set< int > RandomSubset( std::mt19937 &rng, int n, int k ) {
    std::unordered_set< int > temp;
    if( n >= k ) {
      for( int i = n - k; i != n; ++i ) {
        const int t = std::uniform_int_distribution< int >( 0u, i )( rng );
        if( temp.find( t ) != temp.end() ) {
          temp.insert( i );
        }
        else {
          temp.insert( t );
        }
      }
    }
    else {
      for( int i = 0u; i != n; ++i ) {
        temp.insert( i );
      }
    }
    return temp;
  }
  std::unordered_set< std::size_t > RandomSubset( std::mt19937 &rng, std::size_t n, std::size_t k ) {
    std::unordered_set< std::size_t > temp;
    if( n >= k ) {
      for( std::size_t i = n - k; i != n; ++i ) {
        const std::size_t t = std::uniform_int_distribution< std::size_t >( 0u, i )( rng );
        if( temp.find( t ) != temp.end() ) {
          temp.insert( i );
        }
        else {
          temp.insert( t );
        }
      }
    }
    else {
      for( std::size_t i = 0u; i != n; ++i ) {
        temp.insert( i );
      }
    }
    return temp;
  }
  std::vector< BigInt > SampleInt( BigInt min, BigInt max, std::int32_t n ) {
    if( max < min )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
    {
      throw exceptions::invalid_argument( "max < min", __FILE__, __LINE__ );
    }
    if( max - min + 1 <= n ) {
      std::vector< BigInt > temp;
      temp.reserve( std::size_t( max - min + 1 ) );
      for( BigInt i = min; i != max + 1; ++i ) {
        temp.push_back( i );
      }
      return temp;
    }
    else {
      const BigInt delta = ( max - min + 1 ) / n;
      std::vector< BigInt > temp( n );
      for( std::int32_t i = 0; i != n; ++i ) {
        temp[ i ] = min + delta * i;
      }
      return temp;
    }
  }
  void AssertFileExists( const std::function<void(std::string &&)> &sink, const fs::path &file ) {
    if( !fs::exists( file ) ) {
      sink(
        std::string( "Target file ('" ) +
        file.string() +
        "') does not exist"
      );
      std::exit( 1 );
    }
  }
  void WriteFile(
    const std::function<void(std::string &&)> &sink,
    const fs::path &file,
    const std::vector< std::byte > &content
  ) {
    try {
      std::fstream f( file.c_str(), std::ios::out );
      f.write( reinterpret_cast<const char*>( content.data() ), content.size() );
    }
    catch( ... ) {
      Log( sink, std::string( "[Warning] Failed to write file '" ) + file.string() + "'" );
    }
  }
  void RemoveFile(
    const fs::path &file
  ) {
    try {
      fs::remove( file );
    } catch( ... ) {}
  }

}

