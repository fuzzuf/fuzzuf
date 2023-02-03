/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
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
 * @file recursion_info.cpp
 * @brief Recursion of tree
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 *
 * @details This file defines the RecursionInfo class.
 *          RecursionInfo holds the discrete distribution
 *          sampler to pick a node randomly.
 *          It also calculates the parents of each node
 *          and check if the parents share the same non-terminal
 *          (recursion) as that of children.
 */
#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"

#include <algorithm>
#include <iostream>
#include <limits>
#include <numeric>
#include <utility>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

using fuzzuf::utils::random::WalkerDiscreteDistribution;

/**
 * @fn
 * @brief Construct recursion info
 * @param (t) Tree
 * @param (n) Nonterminal ID
 * @param (ctx) Context
 * @return std::nullopt if it cannot find parents, otherwise RecursionInfo
 */
std::optional<RecursionInfo> RecursionInfo::New(Tree& t, const NTermID& n,
                                                Context& ctx) {
  std::unordered_map<NodeID, NodeID> recursive_parents;
  std::vector<NodeID> node_by_offset;
  std::vector<size_t> depth_by_offset;

  std::optional<Parent> r = RecursionInfo::FindParents(t, n, ctx);
  if (!r) {
    return std::nullopt;
  }

  std::tie(recursive_parents, node_by_offset, depth_by_offset) = r.value();

  auto sampler = WalkerDiscreteDistribution<size_t>(depth_by_offset);

  return RecursionInfo(std::move(recursive_parents), std::move(sampler),
                       std::move(depth_by_offset), std::move(node_by_offset));
}

/**
 * @fn
 * @brief Find parents
 * @params (t) Tree
 * @params (nt) Nonterminal ID
 * @params (ctx) Context
 * @return A tuple of NodeID->NodeID map, vector of NodeID, and vector of depth
 * (std::optional)
 */
std::optional<Parent> RecursionInfo::FindParents(Tree& t, const NTermID& nt,
                                                 Context& ctx) {
  using Stack = std::pair<std::optional<NodeID>, size_t>;
  std::vector<Stack> stack;
  stack.emplace_back(std::nullopt, 0);

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
        if (res) std::tie(parents, ids, weights) = res.value();

        parents[node] = maybe_parent.value();
        ids.emplace_back(node);
        weights.emplace_back(depth);

        res = Parent(parents, ids, weights);
      }

      maybe_parent = node;
    }

    size_t n_children = ctx.GetNumChildren(t.rules()[i]);
    for (size_t j = 0; j < n_children; j++) {
      stack.emplace_back(maybe_parent, depth + 1);
    }
  }

  return res;
}

/**
 * @fn
 * @brief Get a random recursion pair
 * @return A pair of Node IDs
 */
std::pair<NodeID, NodeID> RecursionInfo::GetRandomRecursionPair() const {
  return GetRecursionPairByOffset(_sampler());
}

/**
 * @fn
 * @brief Get a recursion pair by offset
 * @param (offset) Offset to get the recursion
 * @return A pair of Node IDs
 */
std::pair<NodeID, NodeID> RecursionInfo::GetRecursionPairByOffset(
    size_t offset) const {
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
size_t RecursionInfo::GetNumberOfRecursions() const {
  return _node_by_offset.size();
}

}  // namespace fuzzuf::algorithm::nautilus::grammartec
