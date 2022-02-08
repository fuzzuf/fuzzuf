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
 * @file recursion_info.hpp
 * @brief Recursion of tree
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <optional>
#include <tuple>
#include <unordered_map>
#include <vector>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

class LoadedDiceSampler {
public:
  struct AliasEntry {
    size_t val;
    size_t alias;
    double prob_of_val;
  };
  LoadedDiceSampler() {} // for vector
  LoadedDiceSampler(std::vector<double>& probs);
  size_t Sample();

private:
  std::vector<AliasEntry> _entries;
};


using Parent = std::tuple<std::unordered_map<NodeID, NodeID>,
                          std::vector<NodeID>,
                          std::vector<size_t>>;

class RecursionInfo {
public:
  RecursionInfo(Tree& t, NTermID n, Context& ctx);
  static std::optional<Parent> FindParents(Tree& t, NTermID nt, Context& ctx);
  static LoadedDiceSampler BuildSampler(std::vector<size_t>& depth);

  std::pair<NodeID, NodeID> GetRandomRecursionPair();
  std::pair<NodeID, NodeID> GetRecursionPairByOffset(size_t offset);
  size_t GetNumberOfRecursions();

private:
  std::unordered_map<NodeID, NodeID> _recursive_parents;
  LoadedDiceSampler _sampler;
  std::vector<size_t> _depth_by_offset;
  std::vector<NodeID> _node_by_offset;
};

} // namespace fuzzuf::algorithms::nautilus::grammartec
