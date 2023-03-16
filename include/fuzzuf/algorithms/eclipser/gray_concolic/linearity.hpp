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
 * @file linearity.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_LINEARITY_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_LINEARITY_HPP
#include <boost/rational.hpp>
#include <nlohmann/json_fwd.hpp>
#include <fuzzuf/algorithms/eclipser/core/bigint.hpp>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>

namespace fuzzuf::algorithm::eclipser::gray_concolic {

using Fraction = boost::rational< BigInt >;

struct Linearity {
  Fraction slope;
  BigInt x0;
  BigInt y0;
  BigInt target;
};

void to_json( nlohmann::json&, const Linearity& );
void from_json( const nlohmann::json&, Linearity& );

Fraction FindCommonSlope(
  std::size_t cmp_size,
  const BigInt &x1,
  const BigInt &x2,
  const BigInt &x3,
  const BigInt &y1,
  const BigInt &y2,
  const BigInt &y3
);

}

#endif


