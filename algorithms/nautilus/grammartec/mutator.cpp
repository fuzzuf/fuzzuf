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
 * @file mutator.cpp
 * @brief Mutator of grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/grammartec/mutator.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

bool Mutator::MinimizeTree(Tree& tree,
                           std::unordered_set<size_t>& bits,
                           Context& ctx,
                           size_t start_index, size_t end_index,
                           FTester& tester) {
  size_t i = start_index;

  while (i < tree.Size()) {
    NodeID n(i);
    NTermID nt = tree.GetRule(n, ctx).Nonterm();

    if (tree.SubTreeSize(n) > ctx.GetMinLenForNT(nt)) {
      _scratchpad.GenerateFromNT(nt, ctx.GetMinLenForNT(nt), ctx);
      if (std::optional<Tree> t = Mutator::TestAndConvert(
            tree, n, _scratchpad, NodeID(0), ctx, bits, tester
          )) {
        tree = t.value();
      }
    }

    if (++i == end_index) {
      return false;
    }
  }

  return true;
};

/**
 * @fn
 * @brief Convert tree after test
 * @param (tree_a) First tree
 * @param (n_a) First node ID
 * @param (tree_b) Second tree
 * @param (n_b) Second node ID
 * @param (ctx) Context
 * @param (fresh_bits) Set of fresh bits
 * @param (tester) Tester
 */
std::optional<Tree> Mutator::TestAndConvert(
  Tree& tree_a, NodeID n_a,
  Tree& tree_b, NodeID n_b,
  Context& ctx,
  std::unordered_set<size_t>& fresh_bits,
  FTester& tester
) {
  TreeMutation repl = tree_a.MutateReplaceFromTree(n_a, tree_b, n_b);
  if (tester(repl, fresh_bits, ctx)) {
    return repl.ToTree(ctx);
  }

  return std::nullopt;
}

} // namespace fuzzuf::algorithms::nautilus::grammartec
