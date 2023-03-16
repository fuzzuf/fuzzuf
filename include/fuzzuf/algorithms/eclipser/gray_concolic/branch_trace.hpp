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
 * @file branch_trace.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_BRANCH_TRACE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_BRANCH_TRACE_HPP

#include <string>
#include <functional>
#include <vector>
#include <utility>
#include "fuzzuf/algorithms/eclipser/core/failwith.hpp"
#include "fuzzuf/algorithms/eclipser/core/bigint.hpp"
#include "fuzzuf/algorithms/eclipser/core/seed.hpp"
#include "fuzzuf/algorithms/eclipser/core/options.hpp"
#include "fuzzuf/algorithms/eclipser/core/branch_info.hpp"

namespace fuzzuf::algorithm::eclipser::gray_concolic {

using BranchTrace = std::vector< BranchInfo >;

namespace branch_trace {

std::pair< std::vector< std::vector< BranchInfo > >, std::vector< seed::Seed > >
CollectAux(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  const std::pair< std::vector< std::vector< BranchInfo > >, std::vector< seed::Seed > > &acc,
  const BigInt &try_val
);

std::pair< std::vector< std::vector< BranchInfo > >, std::vector< seed::Seed > >
Collect(
  const std::function<void(std::string &&)> &sink,
  const seed::Seed &seed,
  const options::FuzzOption &opt,
  const BigInt &min_val,
  const BigInt &max_val
);

struct GetHeadAddr {
  template< typename T >
  std::uint64_t operator()( const T &br_trace ) const {
    if( br_trace.empty() ) {
      failwith( "getHeadAddr() called with an empty list" );
      return 0u; // unreachable
    }
    return br_trace.begin()->inst_addr;
  }
};

struct GetNextAddr {
  template< typename T >
  std::uint64_t operator()( const T &br_trace ) const {
    if( br_trace.empty() ) {
      failwith( "getHeadAddr() called with an empty list" );
      return 0u; // unreachable
    }
    else if( br_trace.size() == 1u ) {
      failwith( "getNextAddr() called with a length-one list" );
      return 0u; // unreachable
    }
    return std::next( br_trace.begin() )->inst_addr;
  }
};

struct IsLongerThanOne {
  template< typename T >
  bool operator()( const T &br_trace ) const {
    return br_trace.size() > 1u;
  }
};

}

}

#endif

