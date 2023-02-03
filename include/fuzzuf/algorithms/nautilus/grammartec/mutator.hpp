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
 * @file mutator.hpp
 * @brief Tree mutation engine
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_MUTATOR_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_MUTATOR_HPP

#include <functional>
#include <optional>
#include <unordered_set>

#include "fuzzuf/algorithms/nautilus/grammartec/chunkstore.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

using FTester =
    std::function<bool(TreeMutation&, std::unordered_set<size_t>&, Context&)>;
using FTesterMut = std::function<void(TreeMutation&, Context&)>;

class Mutator {
 public:
  Mutator(Context& ctx) : _scratchpad(Tree({}, ctx)) {}
  bool MinimizeTree(Tree& tree, std::unordered_set<size_t>& bits, Context& ctx,
                    size_t start_index, size_t end_index,
                    const FTester& tester);
  bool MinimizeRec(Tree& tree, std::unordered_set<size_t>& bits, Context& ctx,
                   size_t start_index, size_t end_index,
                   const FTester& tester) const;
  bool MutRules(Tree& tree, Context& ctx, size_t start_index, size_t end_index,
                const FTesterMut& tester);
  void MutSplice(Tree& tree, Context& ctx, const ChunkStore& cks,
                 const FTesterMut& tester) const;
  void MutRandom(Tree& tree, Context& ctx, const FTesterMut& tester);
  void MutRandomRecursion(Tree& tree,
                          const std::vector<RecursionInfo>& recursions,
                          Context& ctx, const FTesterMut& tester) const;

  static std::optional<NodeID> FindParentWithNT(const Tree& tree,
                                                const NodeID& node,
                                                Context& ctx);
  static std::optional<Tree> TestAndConvert(
      const Tree& tree_a, const NodeID& n_a, const Tree& tree_b,
      const NodeID& n_b, Context& ctx, std::unordered_set<size_t>& fresh_bits,
      const FTester& tester);

 private:
  Tree _scratchpad;
};

}  // namespace fuzzuf::algorithm::nautilus::grammartec

#endif
