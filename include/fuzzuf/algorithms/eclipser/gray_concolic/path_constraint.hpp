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
 * @file path_constraint.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_PATH_CONSTRAINT_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_PATH_CONSTRAINT_HPP
#include <vector>
#include <utility>
#include <variant>
#include <type_traits>
#include <algorithm>
#include <iterator>
#include <nlohmann/json_fwd.hpp>
#include "fuzzuf/algorithms/eclipser/core/bigint.hpp"
#include "fuzzuf/algorithms/eclipser/core/bytes_utils.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::algorithm::eclipser::gray_concolic {

struct Bottom {};
struct Top {};
struct Between {
  BigInt low;
  BigInt high;
};
using Interval = std::variant<
  Between,
  Bottom,
  Top
>;

void to_json( nlohmann::json&, const Bottom& );
void from_json( const nlohmann::json&, Bottom& );
void to_json( nlohmann::json&, const Top& );
void from_json( const nlohmann::json&, Top& );
void to_json( nlohmann::json&, const Between& );
void from_json( const nlohmann::json&, Between& );
void to_json( nlohmann::json&, const Interval& );
void from_json( const nlohmann::json&, Interval& );

namespace interval {

extern const Interval bottom;
extern const Interval top;
Between make( const BigInt &low, const BigInt &high );
Interval Conjunction( const Interval &range1, const Interval &range2 );

}

using ByteConstraint = std::vector< Interval >;

namespace byte_constraint {
  extern const ByteConstraint bot;
  extern const ByteConstraint top;
  bool IsBot( const ByteConstraint &range );
  bool IsTop( const ByteConstraint &range );
  ByteConstraint Make( const std::vector< std::pair< BigInt, BigInt > > &pairs );
  ByteConstraint NormalizeAux(
    const ByteConstraint::const_iterator &ranges_begin,
    const ByteConstraint::const_iterator &ranges_end,
    const ByteConstraint &acc_cond
  );
  ByteConstraint Normalize( const ByteConstraint &ranges );
  ByteConstraint Conjunction(
    const ByteConstraint &cond1,
    const ByteConstraint &cond2
  );
}

using Constraint = std::vector< ByteConstraint >;

namespace constraint {
  extern const Constraint bot;
  extern const Constraint top;
  bool IsBot( const Constraint &range );
  bool IsTop( const Constraint &range );
  Constraint Make(
    const std::vector< std::pair< BigInt, BigInt > > &msb_ranges,
    Endian endian,
    std::size_t size
  );
  Constraint Conjunction(
    const Constraint &cond1,
    const Constraint &cond2
  );
}

}

#endif
