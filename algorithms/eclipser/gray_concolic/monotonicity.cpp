#include <iostream>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/core/failwith.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/monotonicity.hpp>

namespace fuzzuf::algorithm::eclipser::gray_concolic {

void to_json( nlohmann::json &dest, const Tendency &src ) {
  if( src == Tendency::Incr ) {
    dest = "Incr";
  }
  else if( src == Tendency::Decr ) {
    dest = "Incr";
  }
  else {
    dest = "Undetermined";
  }
}

void from_json( const nlohmann::json &src, Tendency &dest ) {
  if( src == "Incr" ) {
    dest = Tendency::Incr;
  }
  else if( src == "Decr" ) {
    dest = Tendency::Decr;
  }
  else {
    dest = Tendency::Undetermined;
  }
}

void to_json( nlohmann::json &dest, const Monotonicity &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "monotonicity";
  dest[ "lower_x" ] = src.lower_x.str();
  if( src.lower_y ) {
    dest[ "lower_y" ] = src.lower_y->str();
  }
  dest[ "upper_x" ] = src.upper_x.str();
  if( src.upper_y ) {
    dest[ "upper_y" ] = src.upper_y->str();
  }
  dest[ "target_y" ] = src.target_y.str();
  dest[ "tendency" ] = src.tendency;
  dest[ "byte_len" ] = src.byte_len;
}

void from_json( const nlohmann::json &src, Monotonicity &dest ) {
  dest = Monotonicity();
  if( src.find( "lower_x" ) != src.end() ) {
    dest.lower_x = BigInt( std::string( src[ "lower_x" ] ) );
  }
  if( src.find( "lower_y" ) != src.end() ) {
    dest.lower_y = BigInt( std::string( src[ "lower_y" ] ) );
  }
  if( src.find( "upper_x" ) != src.end() ) {
    dest.upper_x = BigInt( std::string( src[ "upper_x" ] ) );
  }
  if( src.find( "upper_y" ) != src.end() ) {
    dest.upper_y = BigInt( std::string( src[ "upper_y" ] ) );
  }
  if( src.find( "target_y" ) != src.end() ) {
    dest.target_y = BigInt( std::string( src[ "target_y" ] ) );
  }
  if( src.find( "tendency" ) != src.end() ) {
    dest.tendency = src[ "tendency" ];
  }
  if( src.find( "byte_len" ) != src.end() ) {
    dest.byte_len = src[ "byte_len" ];
  }
}

namespace monotonicity {

namespace {

bool CheckIntermediate(
  Tendency tendency,
  const BigInt &y1,
  const BigInt &y2,
  const BigInt &y3
) {
  if( tendency == Tendency::Incr ) {
    return y1 < y2 && y2 < y3;
  }
  else if( tendency == Tendency::Decr ) {
    return y1 > y2 && y2 > y3;
  }
  else {
    failwith( "Invalid tendency input" );
    return false; // unreachable;
  }
}

Monotonicity Make(
  Tendency tendency,
  const BigInt &a,
  const BigInt &fa,
  const BigInt &b,
  const BigInt &fb,
  const BigInt &k
) {
  return Monotonicity{
    a, fa, b, fb, k, tendency, 1
  };
}

std::optional< Tendency >
CheckMonotonicAux(
  Signedness sign,
  const BigInt &prev_x,
  const BigInt &prev_y,
  Tendency tendency,
  const std::vector< std::pair< BigInt, BigInt > >::const_iterator &coordinates_begin,
  const std::vector< std::pair< BigInt, BigInt > >::const_iterator &coordinates_end
) {
  if( coordinates_begin == coordinates_end ) {
    return tendency;
  }
  const auto &[x,y] = *coordinates_begin;
  if( x <= prev_x ) {
    failwith( "Invalid coordinates" );
    return Tendency::Undetermined; // unreachable
  }
  if( tendency == Tendency::Incr && prev_y <= y ) {
    return CheckMonotonicAux( sign, x, y, Tendency::Incr, std::next( coordinates_begin ), coordinates_end );
  }
  else if( tendency == Tendency::Incr && sign == Signedness::Signed && prev_y > 0 && y < 0 ) {
    return CheckMonotonicAux( sign, x, y, Tendency::Incr, std::next( coordinates_begin ), coordinates_end );
  }
  else if( tendency == Tendency::Decr && prev_y >= y ) {
    return CheckMonotonicAux( sign, x, y, Tendency::Decr, std::next( coordinates_begin ), coordinates_end );
  }
  else if( tendency == Tendency::Decr && sign == Signedness::Signed && prev_y < 0 && y > 0 ) {
    return CheckMonotonicAux( sign, x, y, Tendency::Decr, std::next( coordinates_begin ), coordinates_end );
  }
  else if( tendency == Tendency::Undetermined && prev_y == y ) {
    return CheckMonotonicAux( sign, x, y, Tendency::Undetermined, std::next( coordinates_begin ), coordinates_end );
  }
  else if( tendency == Tendency::Undetermined && prev_y < y ) {
    return CheckMonotonicAux( sign, x, y, Tendency::Incr, std::next( coordinates_begin ), coordinates_end );
  }
  else if( tendency == Tendency::Undetermined && prev_y > y ) {
    return CheckMonotonicAux( sign, x, y, Tendency::Decr, std::next( coordinates_begin ), coordinates_end );
  }
  else {
    return std::nullopt;
  }
}

}

std::optional< Tendency >
CheckMonotonic(
  Signedness sign,
  const std::vector< std::pair< BigInt, BigInt > > &coordinates
) {
  if( coordinates.empty() ) {
    failwith( "Empty coordinate list provided as input" );
    return std::nullopt; // unreachable
  }
  else {
    const auto &[first_x,first_y] = *coordinates.begin();
    return CheckMonotonicAux( sign, first_x, first_y, Tendency::Undetermined, std::next( coordinates.begin() ), coordinates.end() );
  }
}

std::optional< Monotonicity >
GenerateAux(
  Tendency tendency,
  const BigInt &targ_y,
  const BigInt &prev_x,
  const BigInt &prev_y,
  const std::vector< std::pair< BigInt, BigInt > >::const_iterator &coordinates_begin,
  const std::vector< std::pair< BigInt, BigInt > >::const_iterator &coordinates_end
) {
  if( coordinates_begin == coordinates_end ) {
    return std::nullopt;
  }
  else {
    const auto &[x,y] = *coordinates_begin;
    if( prev_y == targ_y || y == targ_y ) {
      return std::nullopt;
    }
    else if( CheckIntermediate( tendency, prev_y, targ_y, y ) ) {
      return Make( tendency, prev_x, prev_y, x, y, targ_y );
    }
    else {
      return GenerateAux( tendency, targ_y, x, y, std::next( coordinates_begin ), coordinates_end );
    }
  }
}

std::optional< Monotonicity >
Generate(
  Tendency tendency,
  const BigInt &targ_y,
  const std::vector< std::pair< BigInt, BigInt > > &coordinates
) {
  if( tendency == Tendency::Undetermined ) {
    failwith( "Invalid tendency input" );
    return std::nullopt; // unreachable
  }
  const auto &[first_x,first_y] = *coordinates.begin();
  return GenerateAux( tendency, targ_y, first_x, first_y, std::next( coordinates.begin() ), coordinates.end() );
}


std::optional< Monotonicity >
Find(
  const std::vector< BranchInfo >::const_iterator &br_infos_begin,
  const std::vector< BranchInfo >::const_iterator &br_infos_end
) {
  if( br_infos_begin == br_infos_end ) {
    failwith( "Empty branchInfo list provided as input" );
    return std::nullopt; // unreachable
  }
  const auto &head_br_info = *br_infos_begin;
  const auto sign = ( head_br_info.branch_type == CompareType::UnsignedSize ) ? Signedness::Unsigned : Signedness::Signed;
  const auto size = head_br_info.operand_size;
  if( std::find_if(
    br_infos_begin,
    br_infos_end,
    [&head_br_info]( const auto &v ) {
      return head_br_info.operand1 != v.operand1;
    }
    ) == br_infos_end ) {
    const auto target_y = branch_info::InterpretAs( sign, size, head_br_info.operand1 );
    std::vector< std::pair< BigInt, BigInt > > coordinates;
    coordinates.reserve( std::distance( br_infos_begin, br_infos_end ) );
    std::transform(
      br_infos_begin,
      br_infos_end,
      std::back_inserter( coordinates ),
      [&]( const auto &br ) {
        return make_pair(
          br.try_value,
          branch_info::InterpretAs( sign, size, br.operand2 )
        );
      }
    );
    const auto tendency = CheckMonotonic( sign, coordinates );
    if( !tendency ) {
      return std::nullopt;
    }
    else {
      return Generate( *tendency, target_y, coordinates );
    }
  }
  else if( std::find_if(
    br_infos_begin,
    br_infos_end,
    [&head_br_info]( const auto &v ) {
      return head_br_info.operand2 != v.operand2;
    }
    ) == br_infos_end ) {
    const auto target_y = branch_info::InterpretAs( sign, size, head_br_info.operand2 );
    std::vector< std::pair< BigInt, BigInt > > coordinates;
    coordinates.reserve( std::distance( br_infos_begin, br_infos_end ) );
    std::transform(
      br_infos_begin,
      br_infos_end,
      std::back_inserter( coordinates ),
      [&]( const auto &br ) {
        return make_pair(
          br.try_value,
          branch_info::InterpretAs( sign, size, br.operand1 )
        );
      }
    );
    const auto tendency = CheckMonotonic( sign, coordinates );
    if( !tendency ) {
      return std::nullopt;
    }
    else {
      return Generate( *tendency, target_y, coordinates );
    }
  }
  else {
    return std::nullopt;
  }
}

Monotonicity AdjustByteLen( const Monotonicity &monotonic ) {
  const auto lower_x = monotonic.lower_x;
  const auto upper_x = monotonic.upper_x;
  if( upper_x - lower_x > 1 ) {
    return monotonic;
  }
  else {
    const auto new_lower_x = lower_x << 8;
    const auto new_upper_x = ( upper_x << 8 ) + 255;
    auto new_monotonic = monotonic;
    new_monotonic.lower_x = new_lower_x;
    new_monotonic.lower_y = std::nullopt;
    new_monotonic.upper_x = new_upper_x;
    new_monotonic.upper_y = std::nullopt;
    new_monotonic.byte_len = monotonic.byte_len + 1;
    return new_monotonic;
  }
}

Monotonicity
UpdateInterval( const Monotonicity monotonic, const BigInt &x, const BigInt &y ) {
  if( monotonic.tendency == Tendency::Incr ) {
    if( y < monotonic.target_y ) {
      auto new_monotonic = monotonic;
      new_monotonic.lower_x = x;
      new_monotonic.lower_y = y;
      return new_monotonic;
    }
    else {
      auto new_monotonic = monotonic;
      new_monotonic.upper_x = x;
      new_monotonic.upper_y = y;
      return new_monotonic;
    }
  }
  else if( monotonic.tendency == Tendency::Decr ) {
    if( y < monotonic.target_y ) {
      auto new_monotonic = monotonic;
      new_monotonic.upper_x = x;
      new_monotonic.upper_y = y;
      return new_monotonic;
    }
    else {
      auto new_monotonic = monotonic;
      new_monotonic.lower_x = x;
      new_monotonic.lower_y = y;
      return new_monotonic;
    }
  }
  else {
    failwith( "Unreachable" );
    return Monotonicity(); // unreachable
  }
}

Monotonicity
Update( const Monotonicity &monotonic, const BigInt &x, const BigInt &y ) {
  return AdjustByteLen( UpdateInterval( monotonic, x, y ) );
}

}

}

