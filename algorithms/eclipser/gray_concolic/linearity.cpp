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
 * @file linearity.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/core/utils.hpp>
#include <fuzzuf/algorithms/eclipser/core/failwith.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/linearity.hpp>

namespace fuzzuf::algorithm::eclipser::gray_concolic {

void to_json( nlohmann::json &dest, const Linearity &src ) {
  dest = nlohmann::json::object();
  dest[ "slope" ] = nlohmann::json::object();
  dest[ "slope" ][ "numerator" ] = src.slope.numerator().str();
  dest[ "slope" ][ "denominator" ] = src.slope.denominator().str();
  dest[ "x0" ] = src.x0.str();
  dest[ "y0" ] = src.y0.str();
  dest[ "target" ] = src.target.str();
}
void from_json( const nlohmann::json &src, Linearity &dest ) {
  dest = Linearity();
  if( src.find( "slope" ) != src.end() ) {
    if(
      src[ "slope" ].find( "numerator" ) != src.end() &&
      src[ "slope" ].find( "denominator" ) != src.end()
    ) {
      dest.slope = Fraction( BigInt( src[ "slope" ][ "numerator" ]. template get< std::string >() ), BigInt( src[ "slope" ][ "denominator" ]. template get< std::string >() ) );
    }
  }
  if( src.find( "x0" ) != src.end() ) {
    dest.x0 = BigInt( src[ "x0" ]. template get< std::string >() );
  }
  if( src.find( "y0" ) != src.end() ) {
    dest.y0 = BigInt( src[ "y0" ]. template get< std::string >() );
  }
  if( src.find( "target" ) != src.end() ) {
    dest.target = BigInt( src[ "target" ]. template get< std::string >() );
  }
}

namespace {

Fraction CalcSlope(
  const BigInt &x1,
  const BigInt &x2,
  const BigInt &y1,
  const BigInt &y2
) {
  return Fraction(
    y2 - y1,
    x2 - x1
  );
}

}

Fraction FindCommonSlope(
  std::size_t cmp_size,
  const BigInt &x1,
  const BigInt &x2,
  const BigInt &x3,
  const BigInt &y1,
  const BigInt &y2,
  const BigInt &y3
) {
  if( x1 >= x2 || x2 >= x3 )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    failwith( "BranchInfo out of order" );
    return Fraction(); // unreachable
  }
  const auto wrapper = GetUnsignedMax( cmp_size + 1u );
  const auto slope12 = CalcSlope( x1, x2, y1, y2 );
  const auto slope23 = CalcSlope( x2, x3, y2, y3 );
  if( slope12 == slope23 ) {
    return slope12;
  }
  else if( y1 < y2 && y3 < y1 && CalcSlope( x2, x3, y2, ( y3 + wrapper ) ) == slope12 ) {
    return slope12;
  }
  else if( y2 > y3 && y1 < y3 && CalcSlope( x1, x2, ( y1 + wrapper ), y2 ) == slope23 ) {
    return slope23;
  }
  else if( y1 > y2 && y3 > y1 && CalcSlope( x2, x3, y2, ( y3 - wrapper ) ) == slope12 ) {
    return slope12;
  }
  else if( y2 < y3 && y1 > y3 && CalcSlope( x1, x2, ( y1 - wrapper ), y2 ) == slope23 ) {
    return slope23;
  }
  else {
    return Fraction( 0, 1 );
  }
}

}

