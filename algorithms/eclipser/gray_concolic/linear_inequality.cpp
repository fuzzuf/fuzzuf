#include <boost/container/static_vector.hpp>
#include <nlohmann/json.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/type_traits/remove_cvr.hpp>
#include <fuzzuf/algorithms/eclipser/core/failwith.hpp>
#include <fuzzuf/algorithms/eclipser/core/utils.hpp>
#include <fuzzuf/algorithms/eclipser/core/options.hpp>
#include <fuzzuf/algorithms/eclipser/core/branch_info.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/linearity.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/linear_equation.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/linear_inequality.hpp>

namespace fuzzuf::algorithm::eclipser::gray_concolic {

void to_json( nlohmann::json &dest, const SimpleLinearInequality &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "simple_linear_inequality";
  dest[ "endian" ] = src.endian;
  dest[ "chunk_size" ] = src.chunk_size;
  dest[ "linearity" ] = src.linearity;
  dest[ "split_points" ] = nlohmann::json::array();
  for( const auto &v: src.split_points ) {
    auto temp = nlohmann::json::array();
    temp.push_back( v.first.str() );
    temp.push_back( v.second.str() );
    dest[ "split_points" ].push_back( std::move( temp ) );
  }
}
void from_json( const nlohmann::json &src, SimpleLinearInequality &dest ) {
  dest = SimpleLinearInequality();
  if( src.find( "endian" ) != src.end() ) {
    dest.endian = src[ "endian" ];
  }
  if( src.find( "chunk_size" ) != src.end() ) {
    dest.chunk_size = src[ "chunk_size" ];
  }
  if( src.find( "linearity" ) != src.end() ) {
    dest.linearity = src[ "linearity" ];
  }
  for( const auto &v: src[ "split_points" ] ) {
    if( v.size() == 2u ) {
      dest.split_points.emplace_back( BigInt( v[ 0 ]. template get< std::string > () ), BigInt( v[ 1 ]. template get< std::string > () ) );
    }
  }
}

void to_json( nlohmann::json &dest, const LinearInequality &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "linear_inequality";
  if( src.tight_inequality ) {
    dest[ "tight_inequality" ] = *src.tight_inequality;
  }
  if( src.loose_inequality ) {
    dest[ "loose_inequality" ] = *src.loose_inequality;
  }
  dest[ "sign" ] = src.sign;
}

void from_json( const nlohmann::json &src, LinearInequality &dest ) {
  dest = LinearInequality();
  if( src.find( "tight_inequality" ) != src.end() ) {
    dest.tight_inequality = LinearEquation( src[ "tight_inequality" ] );
  }
  if( src.find( "loose_inequality" ) != src.end() ) {
    dest.loose_inequality = SimpleLinearInequality( src[ "loose_inequality" ] );
  }
  if( src.find( "sign" ) != src.end() ) {
    dest.sign = src[ "sign" ];
  }
}


namespace linear_inequality {

std::vector< std::byte > ConcatBytes( std::size_t chunk_size, const BranchInfo &br_info, const Context &ctx ) {
  return linear_equation::ConcatBytes( chunk_size, br_info, ctx );
}

namespace {

std::optional< std::pair< BigInt, BigInt > > SolveAux(
  const Fraction &slope,
  BigInt x0,
  BigInt y0,
  Signedness /*sign*/,
  BigInt target_y
) {
  const auto candidate = x0 + ( target_y - y0 ) * slope.denominator() / slope.numerator();
  const auto check_y = y0 + ( candidate - x0 ) * slope.numerator() / slope.denominator();
  if ( target_y == check_y ) {
    return std::make_pair( candidate - 1, candidate + 1 );
  }
  else if ( check_y > target_y && slope.numerator() > 0 ) {
    return std::make_pair( candidate - 1, candidate );
  }
  else if ( check_y > target_y && slope.numerator() < 0 ) {
    return std::make_pair( candidate, candidate + 1 );
  }
  else if ( check_y < target_y && slope.numerator() > 0 ) {
    return std::make_pair( candidate, candidate + 1 );
  }
  else if ( check_y < target_y && slope.numerator() < 0 ) {
    return std::make_pair( candidate - 1, candidate );
  }
  else return std::nullopt;
}

boost::container::static_vector< std::pair< BigInt, BigInt >, 3u > Solve(
  const Fraction &slope,
  BigInt x0,
  BigInt y0,
  BigInt target_y,
  std::size_t chunk_size,
  std::size_t cmp_size,
  Signedness sign
) {
  std::array< BigInt, 3u > target_ys;
  if( sign == Signedness::Signed ) {
    const BigInt signed_wrap = GetSignedMax( cmp_size ) + BigInt( 1 );
    target_ys[ 0 ] = -signed_wrap;
    target_ys[ 1 ] = target_y;
    target_ys[ 2 ] = signed_wrap;
  }
  else if( sign == Signedness::Unsigned ) {
    const BigInt unsigned_wrap = GetUnsignedMax( cmp_size ) + BigInt( 1 );
    target_ys[ 0 ] = 0;
    target_ys[ 1 ] = target_y;
    target_ys[ 2 ] = unsigned_wrap;
  }
  else {
    throw exceptions::invalid_argument( "Unknown signedness", __FILE__, __LINE__ );
  }
  boost::container::static_vector< std::pair< BigInt, BigInt >, 3u > solved;
  for( const auto &y: target_ys ) {
    const auto solved_maybe = SolveAux( slope, x0, y0, sign, y );
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
      const auto &[low,high] = v;
      return !(
        0 <= low &&
        high <= GetUnsignedMax( chunk_size )
      );
    }
  ), solved.end() );
  return solved;
}

Result Generate(
  Endian endian,
  std::size_t chunk_size,
  std::size_t cmp_size,
  const Fraction &slope,
  BigInt target_y,
  BigInt x0,
  BigInt y0,
  Signedness sign
) {
  auto sols = Solve( slope, x0, y0, target_y, chunk_size, cmp_size, sign );
  if( sols.empty() ) {
    return Unsolvable();
  }
  else {
    return Solvable{
      endian, // Endian
      int( chunk_size ), // ChunkSize
      Linearity{ slope, x0, y0, target_y }, // Linearity
      std::move( sols ) // SplitPoints
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
  const auto sign = ( br_info1.branch_type == CompareType::SignedSize ) ? Signedness::Signed : Signedness::Unsigned;
  if( ctx.bytes.size() < chunk_size - 1 ) {
    failwith( "Invalid size" );
    return Result{}; // unreachable
  }
  const auto x1 = BytesToBigInt( endian, ConcatBytes( chunk_size, br_info1, ctx ) );
  const auto x2 = BytesToBigInt( endian, ConcatBytes( chunk_size, br_info2, ctx ) );
  const auto x3 = BytesToBigInt( endian, ConcatBytes( chunk_size, br_info3, ctx ) );
  if( br_info1.operand1 == br_info2.operand1 && br_info2.operand1 == br_info3.operand1 ) {
    const auto y1 = branch_info::InterpretAs( sign, cmp_size, br_info1.operand2 );
    const auto y2 = branch_info::InterpretAs( sign, cmp_size, br_info2.operand2 );
    const auto y3 = branch_info::InterpretAs( sign, cmp_size, br_info3.operand2 );
    const auto slope = FindCommonSlope( cmp_size, x1, x2, x3, y1, y2, y3 );
    if( slope.numerator() == 0 ) {
      return NonLinear();
    }
    else {
      const auto target_y = BigInt( br_info1.operand1 );
      return Generate( endian, chunk_size, cmp_size, slope, target_y, x1, y1, sign );
    }
  }
  else if( br_info1.operand2 == br_info2.operand2 && br_info2.operand2 == br_info3.operand2 ) {
    const auto y1 = branch_info::InterpretAs( sign, cmp_size, br_info1.operand1 );
    const auto y2 = branch_info::InterpretAs( sign, cmp_size, br_info2.operand1 );
    const auto y3 = branch_info::InterpretAs( sign, cmp_size, br_info3.operand1 );
    const auto slope = FindCommonSlope( cmp_size, x1, x2, x3, y1, y2, y3 );
    if( slope.numerator() == 0 ) {
      return NonLinear();
    }
    else {
      const auto target_y = BigInt( br_info1.operand2 );
      return Generate( endian, chunk_size, cmp_size, slope, target_y, x1, y1, sign );
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

std::optional< Solvable > FindLoose(
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

std::optional< LinearInequality > Find(
  const Context &ctx,
  const std::vector< BranchInfo > &br_info_triple
) {
  auto tight_ineq_opt = linear_equation::Find( ctx, br_info_triple );
  auto loose_ineq_opt = FindLoose( ctx, br_info_triple );
  if( !tight_ineq_opt && !loose_ineq_opt ) {
    return std::nullopt;
  }
  const auto &br_info = br_info_triple[ 0 ];
  const auto sign = ( br_info.branch_type == CompareType::SignedSize ) ? Signedness::Signed : Signedness::Unsigned;
  return LinearInequality{
    tight_ineq_opt,
    loose_ineq_opt,
    sign
  };
}

}

}

