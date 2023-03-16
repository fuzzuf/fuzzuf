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
 * @file branch_tree.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_BRANCH_TREE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_GRAY_CONCOLIC_BRANCH_TREE_HPP
#include <unordered_set>
#include <unordered_map>
#include <optional>
#include <variant>
#include <boost/variant.hpp>
#include <boost/range/iterator_range.hpp>
#include "fuzzuf/algorithms/eclipser/gray_concolic/linear_equation.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/linear_inequality.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/monotonicity.hpp"
#include "fuzzuf/algorithms/eclipser/core/options.hpp"
namespace fuzzuf::algorithm::eclipser::gray_concolic {

using SelectSet = std::unordered_set< int >;

using LinEq = LinearEquation;
using LinIneq = LinearInequality;
using Mono = Monotonicity;
using Condition = std::variant<
  LinEq,
  LinIneq,
  Mono
>;

using BranchCondition = std::pair< Condition, BranchPoint >;
using DistanceSign = Sign;

struct BranchSeq {
  int length;
  std::vector< std::pair< BranchCondition, DistanceSign > > branches;
};

namespace branch_seq {

BranchSeq empty();

BranchSeq append(
  const BranchSeq &branch_seq,
  const std::optional< BranchCondition > &branch_cond_opt,
  DistanceSign dist_sign
);

}

using Straight = BranchSeq;
using BranchTree = typename boost::make_recursive_variant<
  Straight,
  std::tuple< BranchSeq, BranchCondition, std::vector< std::pair< DistanceSign, boost::recursive_variant_ > > >,
  std::pair< BranchSeq, std::vector< boost::recursive_variant_ > >
>::type;
using ForkedTree = std::tuple< BranchSeq, BranchCondition, std::vector< std::pair< DistanceSign, BranchTree > > >;
using DivergeTree = std::pair< BranchSeq, std::vector< BranchTree > >;

void to_json( nlohmann::json &dest, const Condition &src );
void from_json( const nlohmann::json &src, Condition &dest );
void to_json( nlohmann::json &dest, const BranchCondition &src );
void from_json( const nlohmann::json &src, BranchCondition &dest );
void to_json( nlohmann::json &dest, const Straight &src );
void from_json( const nlohmann::json &src, Straight &dest );
void to_json( nlohmann::json &dest, const BranchTree &src );
void from_json( const nlohmann::json &src, BranchTree &dest );
void to_json( nlohmann::json &dest, const ForkedTree &src );
void from_json( const nlohmann::json &src, ForkedTree &dest );
void to_json( nlohmann::json &dest, const DivergeTree &src );
void from_json( const nlohmann::json &src, DivergeTree &dest );

namespace branch_tree {

using VisitCntMap = std::unordered_map< std::uint64_t, std::size_t >;
using BrTraceList = std::vector< std::vector< BranchInfo > >;
using BrTraceViewList = std::vector< boost::iterator_range< std::vector< BranchInfo >::const_iterator > >;
using BrInfoCombinations = std::vector< std::vector< std::vector< BranchInfo > > >;
//using BrInfoCombinations = std::vector< BrTraceViewList >;
std::optional< LinEq > InferLinEq(
  const Context &ctx,
  const std::vector< BranchInfo >::const_iterator &br_infos_begin,
  const std::vector< BranchInfo >::const_iterator &br_infos_end
);
BranchTree
MakeAux(
  const options::FuzzOption &opt,
  const Context &ctx,
  const VisitCntMap &visit_cnt_map,
  BrTraceViewList &br_trace_view_list
);
BranchTree
Make(
  const options::FuzzOption &opt,
  const Context &ctx,
  const BrTraceList &br_trace_list
);
BranchTree
SelectAndRepair(
  std::mt19937 &rng,
  const options::FuzzOption &opt,
  const BranchTree &branch_tree
);

}

}

#endif

