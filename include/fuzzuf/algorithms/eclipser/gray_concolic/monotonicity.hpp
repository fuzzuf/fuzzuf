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
 * @file monotonicity.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_MONOTONICITY_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_MONOTONICITY_HPP
#include <vector>
#include <utility>
#include <optional>
#include <config.h>
#ifdef HAS_NLOHMANN_JSON_FWD
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif
#include <fuzzuf/algorithms/eclipser/core/bigint.hpp>
#include <fuzzuf/algorithms/eclipser/core/branch_info.hpp>

namespace fuzzuf::algorithm::eclipser::gray_concolic {

enum class Tendency {
  Incr,
  Decr,
  Undetermined
};

void to_json( nlohmann::json&, const Tendency& );
void from_json( const nlohmann::json&, Tendency& );

struct Monotonicity {
  BigInt lower_x;
  std::optional< BigInt > lower_y;
  BigInt upper_x;
  std::optional< BigInt > upper_y;
  BigInt target_y;
  Tendency tendency = Tendency::Undetermined;
  int byte_len = 0;
};

void to_json( nlohmann::json&, const Monotonicity& );
void from_json( const nlohmann::json&, Monotonicity& );

namespace monotonicity {

std::optional< Tendency >
CheckMonotonic(
  Signedness sign,
  const std::vector< std::pair< BigInt, BigInt > > &coordinates
);
std::optional< Monotonicity >
GenerateAux(
  Tendency tendency,
  const BigInt &targ_y,
  const BigInt &prev_x,
  const BigInt &prev_y,
  const std::vector< std::pair< BigInt, BigInt > >::const_iterator &coordinates_begin,
  const std::vector< std::pair< BigInt, BigInt > >::const_iterator &coordinates_end
);
std::optional< Monotonicity >
Generate(
  Tendency tendency,
  const BigInt &targ_y,
  const std::vector< std::pair< BigInt, BigInt > > &coordinates
);
std::optional< Monotonicity >
Find(
  const std::vector< BranchInfo >::const_iterator &br_infos_begin,
  const std::vector< BranchInfo >::const_iterator &br_infos_end
);
Monotonicity
Update( const Monotonicity &monotonic, const BigInt &x, const BigInt &y );


}

}

#endif

