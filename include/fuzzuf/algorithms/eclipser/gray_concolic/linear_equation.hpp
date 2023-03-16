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
 * @file linear_equation.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_LINEAR_EQUATION_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_LINEAR_EQUATION_HPP
#include <vector>
#include <cstdint>
#include <boost/container/static_vector.hpp>
#include <nlohmann/json_fwd.hpp>
#include <fuzzuf/algorithms/eclipser/core/bytes_utils.hpp>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>
#include <fuzzuf/algorithms/eclipser/core/bigint.hpp>
#include <fuzzuf/algorithms/eclipser/core/branch_info.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/linearity.hpp>

namespace fuzzuf::algorithm::eclipser::gray_concolic {

struct LinearEquation {
  Endian endian = Endian::LE;
  int chunk_size = 0;
  Linearity linearity;
  boost::container::static_vector< BigInt, 3u > solutions;
};

void to_json( nlohmann::json&, const LinearEquation& );
void from_json( const nlohmann::json&, LinearEquation& );

namespace linear_equation {

using Solvable = LinearEquation;
using Result = std::variant<
  NonLinear,
  Unsolvable,
  Solvable
>;

std::vector< std::byte > ConcatBytes( std::size_t chunk_size, const BranchInfo &br_info, const Context &ctx );
std::optional< Solvable > Find(
  const Context &ctx,
  const std::vector< BranchInfo > &br_info_triple
);

}

}

#endif

