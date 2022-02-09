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
#include "fuzzuf/utils/random.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

/**
 * @fn
 * @brief Minimize tree so that it satisfies some constraints
 * @param (tree) Tree
 * @param (bits) Set of bits to be passed to tester
 * @param (ctx) Context
 * @param (start_index) Beginning of node ID
 * @param (end_index) End of node ID
 * @param (tester) Tester function to check if a tree satisfies constraints
 * @return Returns true if minimization is complete, otherwise false
 */
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
        tree = t.value(); // TODO: Check this
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
 * @brief Minimize tree so that it satisfies some constraints
 * @param (tree) Tree
 * @param (bits) Set of bits to be passed to tester
 * @param (ctx) Context
 * @param (start_index) Beginning of node ID
 * @param (end_index) End of node ID
 * @param (tester) Tester function to check if a tree satisfies constraints
 * @return Returns true if minimization is complete, otherwise false
 */
bool Mutator::MinimizeRec(Tree& tree,
                          std::unordered_set<size_t>& bits,
                          Context& ctx,
                          size_t start_index, size_t end_index,
                          FTester& tester) {
  size_t i = start_index;

  while (i < tree.Size()) {
    NodeID n(i);

    if (auto parent = Mutator::FindParentWithNT(tree, n, ctx)) {
      if (auto t = Mutator::TestAndConvert(
            tree, parent.value(), tree, n, ctx, bits, tester
          )) {
        tree = t.value(); // TODO: Check this
        i = static_cast<size_t>(parent.value());
      }
    }

    if (++i == end_index) {
      return false;
    }
  }

  return true;
}

/**
 * @fn
 * @brief Mutate tree and call tester
 * @param (tree) Tree
 * @param (ctx) Context
 * @param (start_index) Beginning of node ID
 * @param (end_index) End of node ID
 * @param (tester) Tester function to check if a tree satisfies constraints
 * @return Returns true if minimization is complete, otherwise false
 */
bool Mutator::MutRules(Tree& tree,
                       Context& ctx,
                       size_t start_index, size_t end_index,
                       FTesterMut& tester) {
  for (size_t i = start_index; i < end_index; i++) {
    if (i == tree.Size()) {
      return true;
    }

    NodeID n(i);
    const RuleID& old_rule_id = tree.GetRuleID(n);
    const std::vector<RuleID>& rule_ids = ctx.GetRulesForNT(
      ctx.GetNT(RuleIDOrCustom(old_rule_id))
    );

    for (const RuleID& new_rule_id: rule_ids) {
      if (old_rule_id != new_rule_id) {
        size_t random_size = ctx.GetRandomLenForRuleID(new_rule_id);
        _scratchpad.GenerateFromRule(new_rule_id, random_size, ctx);

        TreeMutation repl = tree.MutateReplaceFromTree(
          n, _scratchpad, NodeID(0)
        );
        tester(repl, ctx);
      }
    }
  }

  return false;
}

/**
 * @fn
 * @brief Mutate tree and call tester
 * @param (tree) Tree
 * @param (ctx) Context
 * @param (cks) Chunk store
 * @param (tester) Tester function
 */
void Mutator::MutSplice(Tree& tree,
                        Context &ctx,
                        ChunkStore& cks,
                        FTesterMut& tester) {
  NodeID n(utils::random::Random<size_t>(0, tree.Size() - 1));
  const RuleID& old_rule_id = tree.GetRuleID(n);

  if (auto r = cks.GetAlternativeTo(old_rule_id, ctx)) {
    auto& [repl_tree, repl_node] = r.value();
    TreeMutation repl = tree.MutateReplaceFromTree(n, repl_tree, repl_node);
    tester(repl, ctx);
  }
}

/**
 * @fn
 * @brief Mutate tree randomly with recursion
 * @param (tree) Tree
 * @param (recursion) Vector of recursion info
 * @param (ctx) Context
 * @param (tester) Tester function
 */
void Mutator::MutRandomRecursion(Tree& tree,
                                 std::vector<RecursionInfo>& recursions,
                                 Context& ctx,
                                 FTesterMut& tester) {
  if (recursions.size() == 0) return;

  size_t max_len_of_recursions = 2 << utils::random::Random<size_t>(1, 10);

  RecursionInfo& recursion_info = utils::random::Choose(recursions);
  auto [rec0, rec1] = recursion_info.GetRandomRecursionPair();

  size_t recursion_len_pre = static_cast<size_t>(rec1) - static_cast<size_t>(rec0);
  size_t recursion_len_total = tree.SubTreeSize(rec0) - tree.SubTreeSize(rec1);
  size_t recursion_len_post = recursion_len_total - recursion_len_pre;
  size_t num_of_recursions = max_len_of_recursions / recursion_len_total;

  // TODO: remove this assertion
  assert ((ssize_t)recursion_len_pre >= 0);
  assert ((ssize_t)recursion_len_total >= 0);
  assert ((ssize_t)recursion_len_post >= 0);

  /* Insert pre recursion */
  size_t postfix = tree.SubTreeSize(rec1);

  /* reserve: Just allocate buffer to avoid realloc */
  std::vector<RuleIDOrCustom> rules_new;
  rules_new.reserve(recursion_len_pre * num_of_recursions      \
                    + postfix                                  \
                    + recursion_len_post * num_of_recursions);

  std::vector<size_t> sizes_new;
  sizes_new.reserve(recursion_len_pre * num_of_recursions      \
                    + postfix                                  \
                    + recursion_len_post * num_of_recursions);

  for (size_t i = 0; i < num_of_recursions * recursion_len_pre; i++) {
    rules_new.emplace_back(
      tree.GetRuleOrCustom(rec0 + (i % recursion_len_pre))
    );
    sizes_new.emplace_back(
      tree.sizes().at(static_cast<size_t>(rec0) + (i % recursion_len_pre))
    );
  }

  /* Append ending of original tree */
  for (size_t i = 0; i < postfix; i++) {
    rules_new.emplace_back(tree.GetRuleOrCustom(rec1 + i));
    sizes_new.emplace_back(tree.sizes().at(static_cast<size_t>(rec1) + i));
  }

  /* Adjust the sizes */
  for (size_t i = 0; i < num_of_recursions * recursion_len_pre; i++) {
    if (sizes_new[i] >= recursion_len_pre) {
      sizes_new[i] += (num_of_recursions - i / recursion_len_pre - 1)  \
        * recursion_len_total;
    }
  }

  /* Append post recursion */
  for (size_t i = 0; i < num_of_recursions * recursion_len_post; i++) {
    rules_new.emplace_back(
      tree.GetRuleOrCustom(rec1 + postfix + (i % recursion_len_post))
    );
    sizes_new.emplace_back(
      tree.sizes().at(
        static_cast<size_t>(rec1) + postfix + (i % recursion_len_post)
      )
    );
  }

  Tree recursion_tree(rules_new, sizes_new, {});
  TreeMutation repl = tree.MutateReplaceFromTree(
    rec1, recursion_tree, NodeID(0)
  );

  tester(repl, ctx);
}

/**
 * @fn
 * @brief Find parent of a node by Nonterminal
 * @param (tree) Tree
 * @param (node) Node ID to get parent of
 * @param (ctx) Context
 */
std::optional<NodeID> Mutator::FindParentWithNT(
  Tree& tree, const NodeID& node, Context& ctx
) {
  const NTermID& nt = tree.GetRule(node, ctx).Nonterm();

  NodeID cur = node;
  while (std::optional<NodeID> parent = tree.GetParent(cur)) {
    if (tree.GetRule(parent.value(), ctx).Nonterm() == nt) {
      return parent.value();
    }

    cur = parent.value();
  }

  return std::nullopt;
}

/**
 * @fn
 * @brief Convert tree after test
 * @param (tree_a) First tree
 * @param (n_a) First node ID
 * @param (tree_b) Second tree
 * @param (n_b) Second node ID
 * @param (ctx) Context
 * @param (fresh_bits) Set of fresh bits
 * @param (tester) Tester function
 */
std::optional<Tree> Mutator::TestAndConvert(
  Tree& tree_a, const NodeID& n_a,
  Tree& tree_b, const NodeID& n_b,
  Context& ctx,
  std::unordered_set<size_t>& fresh_bits,
  FTester& tester
) {
  TreeMutation repl = tree_a.MutateReplaceFromTree(n_a, tree_b, n_b);
  if (tester(repl, fresh_bits, ctx)) {
    /* Mutated to a tree satisfying constraints by tester */
    return repl.ToTree(ctx);
  }

  return std::nullopt;
}

} // namespace fuzzuf::algorithms::nautilus::grammartec
