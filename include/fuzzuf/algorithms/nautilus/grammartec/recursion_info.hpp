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
 * @file recursion_info.hpp
 * @brief Recursion of tree
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_RECURSION_INFO_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_RECURSION_INFO_HPP

#include <memory>
#include <optional>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

using fuzzuf::utils::random::WalkerDiscreteDistribution;

using Parent = std::tuple<std::unordered_map<NodeID, NodeID>,
                          std::vector<NodeID>, std::vector<size_t>>;

class RecursionInfo {
 public:
  RecursionInfo() = delete;
  static std::optional<RecursionInfo> New(Tree& t, const NTermID& n,
                                          Context& ctx);

  std::pair<NodeID, NodeID> GetRandomRecursionPair() const;
  std::pair<NodeID, NodeID> GetRecursionPairByOffset(size_t offset) const;
  size_t GetNumberOfRecursions() const;

  static std::optional<Parent> FindParents(Tree& t, const NTermID& nt,
                                           Context& ctx);

 private:
  RecursionInfo(std::unordered_map<NodeID, NodeID>&& recursive_parents,
                WalkerDiscreteDistribution<size_t>&& sampler,
                std::vector<size_t>&& depth_by_offset,
                std::vector<NodeID>&& node_by_offset)
      : _recursive_parents(std::move(recursive_parents)),
        _sampler(std::move(sampler)),
        _depth_by_offset(std::move(depth_by_offset)),
        _node_by_offset(std::move(node_by_offset)) {}

  std::unordered_map<NodeID, NodeID> _recursive_parents;
  WalkerDiscreteDistribution<size_t> _sampler;
  std::vector<size_t> _depth_by_offset;
  std::vector<NodeID> _node_by_offset;
};

}  // namespace fuzzuf::algorithm::nautilus::grammartec

#endif
