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
 * @file linear_equation.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <boost/container/static_vector.hpp>
#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/core/executor.hpp>
#include <fuzzuf/algorithms/eclipser/core/seed.hpp>
#include <fuzzuf/algorithms/eclipser/core/utils.hpp>
#include <fuzzuf/algorithms/eclipser/core/options.hpp>
#include <fuzzuf/algorithms/eclipser/core/failwith.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/linear_equation.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/linearity.hpp>

namespace fuzzuf::algorithm::eclipser::gray_concolic {

void to_json( nlohmann::json &dest, const LinearEquation &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "linear_equation";
  dest[ "endian" ] = nlohmann::json( src.endian );
  dest[ "chunk_size" ] = src.chunk_size;
  dest[ "linearity" ] = nlohmann::json( src.linearity );
  dest[ "solutions" ] = nlohmann::json::array();
  for( const auto &s: src.solutions ) {
   dest[ "solutions" ].push_back( s.str() ) ;
  }
}

void from_json( const nlohmann::json &src, LinearEquation &dest ) {
  dest = LinearEquation();
  if( src.find( "endian" ) != src.end() ) {
    dest.endian = src[ "endian" ];
  }
  if( src.find( "chunk_size" ) != src.end() ) {
    dest.chunk_size = src[ "chunk_size" ];
  }
  if( src.find( "linearity" ) != src.end() ) {
    dest.linearity = src[ "linearity" ];
  }
  if( src.find( "solutions" ) != src.end() ) {
    for( const auto &s: src[ "solutions" ] ) {
      dest.solutions.push_back( BigInt( s. template get< std::string >() ) );
    }
  }
}

namespace linear_equation {

std::vector< std::byte > ConcatBytes( std::size_t chunk_size, const BranchInfo &br_info, const Context &ctx ) {
  const auto try_byte = br_info.try_value;
  if( ctx.byte_dir == Direction::Stay )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    failwith( "Byte cursor cannot be staying" );
    return std::vector< std::byte >(); // unreachable
  }
  else if( ctx.byte_dir == Direction::Left ) {
    const auto len = ctx.bytes.size();
    std::vector< std::byte > bytes(
      std::next( ctx.bytes.begin(), len - chunk_size + 1 ),
      ctx.bytes.end()
    );
    bytes.push_back( std::byte( std::uint8_t( try_byte ) ) );
    return bytes;
  }
  else if( ctx.byte_dir == Direction::Right ) {
    std::vector< std::byte > bytes;
    bytes.reserve( ctx.bytes.size() + 1u );
    bytes.push_back( std::byte( std::uint8_t( try_byte ) ) );
    bytes.insert(
      bytes.end(),
      ctx.bytes.begin(),
      std::next( ctx.bytes.begin(), chunk_size - 1 )
    );
    return bytes;
  }
  else
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    std::abort();
  }
}

namespace {

std::optional< BigInt > SolveAux(
  const Fraction &slope,
  BigInt x0,
  BigInt y0,
  BigInt target_y
) {
  const auto candidate = x0 + ( target_y - y0 ) * slope.denominator() / slope.numerator();
  if ( target_y - y0 == ( candidate - x0 ) * slope.numerator() / slope.denominator() ) {
    return candidate;
  }
  else {
    return std::nullopt;
  }
}

boost::container::static_vector< BigInt, 3u > Solve(
  const Fraction &slope,
  BigInt x0,
  BigInt y0,
  BigInt target_y,
  std::size_t chunk_size,
  std::size_t cmp_size
) {
  const BigInt unsigned_wrap = GetUnsignedMax( cmp_size ) + BigInt( 1 );
  std::array< BigInt, 3u > target_ys;
  target_ys[ 0 ] = target_y;
  target_ys[ 1 ] = target_y + unsigned_wrap;
  target_ys[ 2 ] = target_y - unsigned_wrap;
  boost::container::static_vector< BigInt, 3u > solved;
  for( const auto &y: target_ys ) {
    const auto solved_maybe = SolveAux( slope, x0, y0, y );
    if( solved_maybe ) {
      solved.push_back( *solved_maybe );
    }
  }
  std::sort( solved.begin(), solved.end() );
  auto unique_end = std::unique( solved.begin(), solved.end() );
  solved.erase( std::remove_if(
    solved.begin(),
    unique_end,
    [chunk_size]( const auto &v ) {
      return !(
        0 <= v &&
        v <= GetUnsignedMax( chunk_size )
      );
    }
  ), solved.end() );
  return solved;
}

Result Generate(
  Endian endian,
  std::size_t chunk_size,
  std::size_t cmp_size,
  Fraction slope,
  BigInt target_y,
  BigInt x0,
  BigInt y0
) {
  auto sols = Solve( slope, x0, y0, target_y, chunk_size, cmp_size );
  if( sols.empty() ) {
    return Unsolvable();
  }
  else {
    return Solvable{
      endian,
      int( chunk_size ),
      Linearity{ slope, x0, y0, target_y },
      std::move( sols )
    };
  }
}

Result FindAsNByteChunk(
  const Context &ctx,
  Endian endian,
  std::size_t chunk_size,
  const BranchInfo &br_info1,
  const BranchInfo &br_info2,
  const BranchInfo &br_info3
) {
  const std::size_t cmp_size = br_info1.operand_size;
  if( ctx.bytes.size() < chunk_size - 1 )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    failwith( "Invalid size" );
  }
  const auto x1 = BytesToBigInt( endian, ConcatBytes( chunk_size, br_info1, ctx ) );
  const auto x2 = BytesToBigInt( endian, ConcatBytes( chunk_size, br_info2, ctx ) );
  const auto x3 = BytesToBigInt( endian, ConcatBytes( chunk_size, br_info3, ctx ) );
  if( br_info1.operand1 == br_info2.operand1 && br_info2.operand1 == br_info3.operand1 ) {
    const auto y1 = BigInt( br_info1.operand2 );
    const auto y2 = BigInt( br_info2.operand2 );
    const auto y3 = BigInt( br_info3.operand2 );
    const auto slope = FindCommonSlope( cmp_size, x1, x2, x3, y1, y2, y3 );
    if( slope.numerator() == 0 ) {
      return NonLinear();
    }
    else {
      const auto target_y = BigInt( br_info1.operand1 );
      return Generate( endian, chunk_size, cmp_size, slope, target_y, x1, y1 );
    }
  }
  else if( br_info1.operand2 == br_info2.operand2 && br_info2.operand2 == br_info3.operand2 ) {
    const auto y1 = BigInt( br_info1.operand1 );
    const auto y2 = BigInt( br_info2.operand1 );
    const auto y3 = BigInt( br_info3.operand1 );
    const auto slope = FindCommonSlope( cmp_size, x1, x2, x3, y1, y2, y3 );
    if( slope.numerator() == 0 ) {
      return NonLinear();
    }
    else {
      const auto target_y = BigInt( br_info1.operand2 );
      return Generate( endian, chunk_size, cmp_size, slope, target_y, x1, y1 );
    }
  }
  else {
    return NonLinear();
  }
}

std::optional< Solvable > FindAux(
  const Context &ctx,
  const std::array< std::pair< Endian, std::size_t >, 7u >::const_iterator &types_begin,
  const std::array< std::pair< Endian, std::size_t >, 7u >::const_iterator &types_end,
  const std::vector< BranchInfo > &br_info_triple
) {
  if( types_begin == types_end ) {
    return std::nullopt;
  }
  const auto &[endian,chunk_size] = *types_begin;
  return std::visit(
    [&]( const auto &v ) -> std::optional< Solvable >  {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, NonLinear > ) {
        return std::nullopt;
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Unsolvable > ) {
        return FindAux( ctx, std::next( types_begin ), types_end, br_info_triple );
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Solvable > ) {
        return v;
      }
      else {
        return std::nullopt;
      }
    },
    FindAsNByteChunk(
      ctx,
      endian,
      chunk_size,
      br_info_triple[ 0 ],
      br_info_triple[ 1 ],
      br_info_triple[ 2 ]
    )
  );
}

}

std::optional< Solvable > Find(
  const Context &ctx,
  const std::vector< BranchInfo > &br_info_triple
) {
  constexpr std::array< std::pair< Endian, std::size_t >, 7u > types{{
    { Endian::BE, 1u },
    { Endian::BE, 2u },
    { Endian::LE, 2u },
    { Endian::BE, 4u },
    { Endian::LE, 4u },
    { Endian::BE, 8u },
    { Endian::LE, 8u }
  }};
  const auto max_len = ctx.bytes.size() + 1u;
  const auto types_end = std::find_if(
    types.begin(),
    types.end(),
    [max_len]( const auto &v ) {
      return v.second > max_len;
    }
  );
  return FindAux( ctx, types.begin(), types_end, br_info_triple );
}

}

}

