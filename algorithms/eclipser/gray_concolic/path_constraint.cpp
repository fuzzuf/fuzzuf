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
 * @file path_constraint.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <nlohmann/json.hpp>
#include "fuzzuf/algorithms/eclipser/gray_concolic/path_constraint.hpp"

namespace fuzzuf::algorithm::eclipser::gray_concolic {

void to_json( nlohmann::json &dest, const Bottom& ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "bottom";
}
void from_json( const nlohmann::json&, Bottom &dest ) {
  dest = Bottom{};
}
void to_json( nlohmann::json &dest, const Top& ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "top";
}
void from_json( const nlohmann::json&, Top &dest ) {
  dest = Top{};
}
void to_json( nlohmann::json &dest, const Between &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "between";
  dest[ "low" ] = src.low.str();
  dest[ "high" ] = src.high.str();
}
void from_json( const nlohmann::json &src, Between &dest ) {
  dest = Between{};
  if( src.find( "low" ) != src.end() ) {
    dest.low = BigInt( src[ "low" ]. template get< std::string >() );
  }
  if( src.find( "high" ) != src.end() ) {
    dest.high = BigInt( src[ "high" ]. template get< std::string >() );
  }
}
void to_json( nlohmann::json &dest, const Interval &src ) {
  dest = std::visit(
    []( const auto &v ) {
      return nlohmann::json( v );
    },
    src
  );
}
void from_json( const nlohmann::json &src, Interval &dest ) {
  dest = Interval{};
  if( src.find( "type" ) != src.end() ) {
    const std::string type = src[ "type" ];
    if( type == "bottom" ) {
      dest = Bottom{};
    }
    else if( type == "bottom" ) {
      dest = Top{};
    }
    if( type == "between" ) {
      Between temp;
      from_json( src, temp );
      dest = temp;
    }
  }
}

namespace interval {
const Interval bottom = Bottom{};
const Interval top = Top{};
Between Make( const BigInt &low, const BigInt &high ) {
  return Between{ low, high };
}
Interval Conjunction( const Interval &range1, const Interval &range2 ) {
  return std::visit(
    []( const auto &range1, const auto &range2 ) -> Interval {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( range1 ) >, Top > ) {
        return range2;
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( range2 ) >, Top > ) {
        return range1;
      }
      else if constexpr (
        std::is_same_v< utils::type_traits::RemoveCvrT< decltype( range1 ) >, Bottom > ||
        std::is_same_v< utils::type_traits::RemoveCvrT< decltype( range2 ) >, Bottom >
      ) {
        return Bottom{};
      }
      else {
        if( range1.high < range2.low || range2.high < range1.low ) {
          return Bottom{};
        }
        else {
          return Between{
            std::max( range1.low, range2.low ),
            std::min( range1.high, range2.high )
          };
        }
      }
    },
    range1, range2
  );
}

}

namespace byte_constraint {

const ByteConstraint bot = ByteConstraint{};
const ByteConstraint top = ByteConstraint{ interval::top };
bool IsBot( const ByteConstraint &range ) {
  return std::find_if(
    range.begin(),
    range.end(),
    []( const auto &r ) {
      return std::visit(
        []( const auto &v ) {
          return !std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Bottom >;
        },
        r
      );
    }
  ) == range.end();
}
bool IsTop( const ByteConstraint &range ) {
  return std::find_if(
    range.begin(),
    range.end(),
    []( const auto &r ) {
      return std::visit(
        []( const auto &v ) {
          return std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Top >;
        },
        r
      );
    }
  ) != range.end();
}
ByteConstraint Make( const std::vector< std::pair< BigInt, BigInt > > &pairs ) {
  ByteConstraint temp;
  temp.reserve( pairs.size() );
  std::transform(
    pairs.begin(),
    pairs.end(),
    std::back_inserter( temp ),
    []( const auto &v ) {
      return interval::Make( v.first, v.second );
    }
  );
  return temp;
}
namespace {
ByteConstraint &NormalizeAux(
  const ByteConstraint::const_iterator &ranges_begin,
  const ByteConstraint::const_iterator &ranges_end,
  ByteConstraint &acc_cond
) {
  if( ranges_begin == ranges_end ) {
    return acc_cond;
  }
  return std::visit(
    [&]( const auto &v ) -> ByteConstraint& {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Bottom > ) {
        return NormalizeAux(
          std::next( ranges_begin ),
          ranges_end,
          acc_cond
        );
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Top > ) {
        acc_cond = top;
        return acc_cond;
      }
      else {
        acc_cond.push_back( v );
        return NormalizeAux( 
          std::next( ranges_begin ),
          ranges_end,
          acc_cond
        );
      }
    },
    *ranges_begin
  );
}
}
ByteConstraint Normalize( const ByteConstraint &ranges ) {
  ByteConstraint acc_cond;
  NormalizeAux( ranges.begin(), ranges.end(), acc_cond );
  std::reverse( acc_cond.begin(), acc_cond.end() );
  return acc_cond;
}
ByteConstraint Conjunction(
  const ByteConstraint &cond1,
  const ByteConstraint &cond2
) {
  ByteConstraint temp;
  for( auto &r1: cond1 )  {
    for( auto &r2: cond2 ) {
      temp.push_back( interval::Conjunction( r1, r2 ) );
    }
  }
  return temp;
}

}

namespace constraint {
const Constraint bot = { byte_constraint::bot };
const Constraint top = Constraint{};
bool IsBot( const Constraint &range ) {
  return std::find_if(
    range.begin(),
    range.end(),
    []( const auto &r ) {
      return byte_constraint::IsBot( r );
    }
  ) != range.end();
}
bool IsTop( const Constraint &range ) {
  return std::find_if(
    range.begin(),
    range.end(),
    []( const auto &r ) {
      return !byte_constraint::IsTop( r );
    }
  ) == range.end();
}
Constraint Make(
  const std::vector< std::pair< BigInt, BigInt > > &msb_ranges,
  Endian endian,
  std::size_t size
) {
  if( endian == Endian::BE ) {
    return Constraint{ byte_constraint::Make( msb_ranges ) };
  }
  else {
    Constraint temp( size - 1u, byte_constraint::top );
    temp.push_back( byte_constraint::Make( msb_ranges ) );
    return temp;
  }
}
Constraint Conjunction(
  const Constraint &cond1,
  const Constraint &cond2
) {
  Constraint temp;
  auto i1 = cond1.begin();
  auto i2 = cond2.begin();
  for( ; i1 != cond1.end() && i2 != cond2.end(); ++i1, ++i2 ) {
    temp.push_back( byte_constraint::Conjunction( *i1, *i2 ) );
  }
  for( ; i1 != cond1.end(); ++i1 ) {
    temp.push_back( byte_constraint::Conjunction( *i1, byte_constraint::top ) );
  }
  for( ; i2 != cond2.end(); ++i2 ) {
    temp.push_back( byte_constraint::Conjunction( byte_constraint::top, *i2 ) );
  }
  return temp;
}
}

}

