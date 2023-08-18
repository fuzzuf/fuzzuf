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
 * @file gray_concolic.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <nlohmann/json.hpp>
#include "fuzzuf/algorithms/eclipser/core/executor.hpp"
#include "fuzzuf/algorithms/eclipser/core/seed.hpp"
#include <fuzzuf/algorithms/eclipser/core/byte_val.hpp>
#include <fuzzuf/algorithms/eclipser/core/failwith.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/branch_trace.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/branch_tree.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/gray_concolic.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/solve.hpp>

namespace fuzzuf::algorithm::eclipser::gray_concolic {

namespace {

std::vector< std::tuple< seed::Seed, Signal, CoverageGain > >
ReconsideCandidates(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const std::vector< seed::Seed > &seeds
) {
  std::vector< std::tuple< seed::Seed, Signal, CoverageGain > > zipped;
  zipped.reserve( seeds.size() );
  for( const auto &seed: seeds ) {
    auto [signal,cov_gain] = executor::GetCoverage( sink, opt, seed );
    zipped.emplace_back(
      seed,
      signal,
      cov_gain
    );
  }
  return zipped;
}

}

std::vector< std::tuple< seed::Seed, Signal, CoverageGain > >
Run(
  const std::function<void(std::string &&)> &sink,
  std::mt19937 &rng,
  const options::FuzzOption &opt,
  const seed::Seed &seed
) {
  const auto cur_byte_val = seed.GetCurByteVal();
  const auto [min_byte,max_byte] = byteval::GetMinMax( cur_byte_val, seed.source );
  if( min_byte == max_byte )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    std::string message( "Cursor pointing to Fixed ByteVal " );
    message += nlohmann::json( seed ).dump();
    failwith( message.c_str() );
    return std::vector< std::tuple< seed::Seed, Signal, CoverageGain > >(); // unreachable
  }
  const auto min_val = BigInt( min_byte ); 
  const auto max_val = BigInt( max_byte );
  const auto [branch_traces,candidates] = branch_trace::Collect( sink, seed, opt, min_val, max_val );
  const auto byte_dir = seed.GetByteCursorDir();
  const auto bytes = seed.QueryNeighborBytes( byte_dir );
  Context ctx{ bytes, byte_dir };
  auto branch_tree__ = branch_tree::Make( opt, ctx, branch_traces );
  const auto branch_tree_ = branch_tree::SelectAndRepair(
    rng,
    opt,
    std::move( branch_tree__ )
  );
  gray_solver::ClearSolutionCache();
  auto solutions = gray_solver::Solve( sink, seed, opt, byte_dir, branch_tree_ );
  const auto by_products = ReconsideCandidates(
    sink, opt, candidates
  );
  solutions.insert(
    solutions.end(),
    by_products.begin(),
    by_products.end()
  );
  return solutions;
}

}

