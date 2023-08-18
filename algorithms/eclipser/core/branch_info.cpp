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
 * @file branch_info.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <string>
#include <type_traits>
#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/core/utils.hpp>
#include <fuzzuf/algorithms/eclipser/core/branch_info.hpp>
#include <fuzzuf/utils/type_traits/remove_cvr.hpp>

namespace fuzzuf::algorithm::eclipser {

void to_json( nlohmann::json &dest, const CompareType &src ) {
  if( src == CompareType::Equality ) {
    dest = "Equality";
  }
  else if( src == CompareType::SignedSize ) {
    dest = "SignedSize";
  }
  else if( src == CompareType::UnsignedSize ) {
    dest = "UnsignedSize";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, CompareType &dest ) {
  if( src.is_string() ) {
    if( src == "Equality" ) {
      dest = CompareType::Equality;
    }
    else if( src == "SignedSize" ) {
      dest = CompareType::SignedSize;
    }
    else if( src == "UnsignedSize" ) {
      dest = CompareType::UnsignedSize;
    }
    else {
      dest = CompareType::Equality;
    }
  }
  else if( src.is_number() ) {
    dest = CompareType( int( src ) );
  }
  else {
    dest = CompareType::Equality;
  }
}

void to_json( nlohmann::json &dest, const BranchPoint &src ) {
  dest = nlohmann::json::object();
  dest[ "addr" ] = src.addr;
  dest[ "idx" ] = src.idx;
}

void from_json( const nlohmann::json &src, BranchPoint &dest ) {
  dest = BranchPoint();
  if( src.find( "addr" ) != src.end() ) {
    dest.addr = src[ "addr" ];
  }
  if( src.find( "idx" ) != src.end() ) {
    dest.idx = src[ "idx" ];
  }
}

void to_json( nlohmann::json &dest, const BranchInfo &src ) {
  dest = nlohmann::json::object();
  dest[ "inst_addr" ] = src.inst_addr;
  dest[ "branch_type" ] = src.branch_type;
  dest[ "try_value" ] = src.try_value.str();
  dest[ "operand_size" ] = src.operand_size;
  dest[ "operand1" ] = src.operand1;
  dest[ "operand2" ] = src.operand2;
  dest[ "distance" ] = src.distance.str();
}

void from_json( const nlohmann::json &src, BranchInfo &dest ) {
  dest.inst_addr = src[ "inst_addr" ];
  dest.branch_type = src[ "branch_type" ];
  dest.try_value = BigInt( src[ "try_value" ]. template get< std::string >() );
  dest.operand_size = src[ "operand_size" ];
  dest.operand1 = src[ "operand1" ];
  dest.operand2 = src[ "operand2" ];
  dest.distance = BigInt( src[ "distance" ]. template get< std::string >() );
}

namespace branch_info {

BigInt InterpretAs(
  Signedness sign,
  std::size_t size,
  std::uint64_t x
) {
  if( sign == Signedness::Signed ) {
    const auto signed_max = GetSignedMax( size );
    const auto x_ = BigInt( x );
    if( x > signed_max ) {
      return x - GetUnsignedMax( size ) - 1;
    }
    else {
      return x;
    }
  }
  else {
    return BigInt( x );
  }
}

}

}

