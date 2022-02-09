/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file tree.cpp
 * @brief Tree for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <algorithm>
#include <iostream>
#include <limits>
#include <numeric>
#include <utility>
#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/random.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

using fuzzuf::utils::random::WalkerDiscreteDistribution;

/**
 * @fn
 * @brief Construct recursion info
 * @param (t) Tree
 * @param (n) Nonterminal ID
 * @param (ctx) Context
 * @note This constructor may throw an exception of `const char*`
 */
RecursionInfo::RecursionInfo(Tree& t, NTermID n, Context& ctx) {
  std::unordered_map<NodeID, NodeID> recursive_parents;
  std::vector<NodeID> node_by_offset;
  std::vector<size_t> depth_by_offset;

  std::optional<Parent> r = RecursionInfo::FindParents(t, n, ctx);
  if (!r)
    throw "Cannot find parents";

  std::tie(recursive_parents, node_by_offset, depth_by_offset) = r.value();

  auto sampler = RecursionInfo::BuildSampler(depth_by_offset);

  _recursive_parents = recursive_parents;
  _sampler = sampler;
  _node_by_offset = node_by_offset;
  _depth_by_offset = depth_by_offset;
}

/**
 * @fn
 * @brief Find parents
 * @params (t) Tree
 * @params (nt) Nonterminal ID
 * @params (ctx) Context
 * @return A tuple of NodeID->NodeID map, vector of NodeID, and vector of depth (std::optional)
 */
std::optional<Parent> RecursionInfo::FindParents(
  Tree& t, NTermID nt, Context& ctx
) {
  using Stack = std::pair<std::optional<NodeID>, size_t>;
  std::vector<Stack> stack;
  stack.push_back(Stack(std::nullopt, 0));

  std::optional<Parent> res = std::nullopt;

  for (size_t i = 0; i < t.rules().size(); i++) {
    NodeID node(i);
    auto [maybe_parent, depth] = stack.back();
    stack.pop_back();

    if (ctx.GetNT(t.rules()[i]) == nt) {
      if (maybe_parent) {
        std::unordered_map<NodeID, NodeID> parents;
        std::vector<NodeID> ids;
        std::vector<size_t> weights;
        if (res)
          std::tie(parents, ids, weights) = res.value();

        parents[node] = maybe_parent.value();
        ids.push_back(node);
        weights.push_back(depth);

        res = Parent(parents, ids, weights);
      }

      maybe_parent = node;
    }

    for (size_t j = 0; j < ctx.GetNumChildren(t.rules()[i]); j++) {
      stack.push_back(Stack(maybe_parent, depth + 1));
    }
  }

  return res;
}

/**
 * @fn
 * @brief Normalize depth and build sampler
 * @param (depth) Vector of depth
 * @return Discrete distribution sampler
 */
WalkerDiscreteDistribution<size_t> RecursionInfo::BuildSampler(
  std::vector<size_t>& depth
) {
  return WalkerDiscreteDistribution<size_t>(depth);
}

/**
 * @fn
 * @brief Get a random recursion pair
 * @return A pair of Node IDs
 */
std::pair<NodeID, NodeID> RecursionInfo::GetRandomRecursionPair()  {
  return GetRecursionPairByOffset(_sampler());
}

/**
 * @fn
 * @brief Get a recursion pair by offset
 * @param (offset) Offset to get the recursion
 * @return A pair of Node IDs
 */
std::pair<NodeID, NodeID> RecursionInfo::GetRecursionPairByOffset(
  size_t offset
) {
  NodeID node1 = _node_by_offset.at(offset);
  NodeID node2 = node1;

  for (size_t i = 0; i < _depth_by_offset.at(offset); i++) {
    node2 = _recursive_parents.at(node1);
  }

  return std::pair<NodeID, NodeID>(node2, node1);
}

/**
 * @fn
 * @brief Get number of recursions
 * @return Number of recursions
 */
size_t RecursionInfo::GetNumberOfRecursions() {
  return _node_by_offset.size();
}

} // namespace fuzzuf::algorithms::nautilus::grammartec
