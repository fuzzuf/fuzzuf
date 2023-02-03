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
#define BOOST_TEST_MODULE nautilus.mutator
#define BOOST_TEST_DYN_LINK

#include "fuzzuf/algorithms/nautilus/grammartec/mutator.hpp"

#include <boost/test/unit_test.hpp>
#include <unordered_set>

#include "fuzzuf/algorithms/nautilus/grammartec/chunkstore.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"

using namespace fuzzuf::algorithm::nautilus::grammartec;

BOOST_AUTO_TEST_CASE(NautilusGrammartecMutatorMutRandomRecursion) {
  RuleID r1(0);
  RuleID r2(1);
  RuleID r3(2);
  RuleID r4(3);
  RuleID r5(4);

  Context ctx;
  ctx.AddRule("N1", "r1{N2}{N3}{N4}");
  ctx.AddRule("N2", "r2");
  ctx.AddRule("N3", "r3{N1}");
  ctx.AddRule("N1", "r4");
  ctx.AddRule("N4", "r5");

  std::vector<RuleIDOrCustom> rules{
      RuleIDOrCustom(r1), RuleIDOrCustom(r2), RuleIDOrCustom(r3),
      RuleIDOrCustom(r4), RuleIDOrCustom(r5),
  };
  Tree tree(std::move(rules), ctx);

  Mutator mutator(ctx);
  FTesterMut tester = [&r1, &r2, &r3, &r4, &r5](TreeMutation& tree_mut,
                                                Context&) {
    BOOST_CHECK(tree_mut.prefix().at(0) == RuleIDOrCustom(r1));
    BOOST_CHECK(tree_mut.prefix().at(1) == RuleIDOrCustom(r2));
    BOOST_CHECK(tree_mut.prefix().at(2) == RuleIDOrCustom(r3));

    BOOST_CHECK(tree_mut.postfix().at(0) == RuleIDOrCustom(r5));

    BOOST_CHECK(tree_mut.repl().at(0) == RuleIDOrCustom(r1));
    BOOST_CHECK(tree_mut.repl().at(1) == RuleIDOrCustom(r2));
    BOOST_CHECK(tree_mut.repl().at(2) == RuleIDOrCustom(r3));
    BOOST_CHECK(tree_mut.repl().back() == RuleIDOrCustom(r5));
  };

  auto recursions = tree.CalcRecursions(ctx);
  BOOST_CHECK(recursions);

  mutator.MutRandomRecursion(tree, recursions.value(), ctx, tester);
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecMutatorMinimizeTree) {
  Context ctx;
  RuleID r1 = ctx.AddRule("S", "s1 {A}");
  ctx.AddRule("S", "s2");
  ctx.AddRule("S", "a1");
  RuleID r2 = ctx.AddRule("A", "a1 {B}");
  ctx.AddRule("A", "a1");
  ctx.AddRule("A", "a2");
  RuleID r3 = ctx.AddRule("B", "b1");
  ctx.AddRule("B", "b2");
  ctx.AddRule("B", "b3{B}");
  ctx.Initialize(10);

  for (size_t i = 0; i < 100; i++) {
    std::vector<RuleIDOrCustom> rules{RuleIDOrCustom(r1), RuleIDOrCustom(r2),
                                      RuleIDOrCustom(r3)};
    Tree tree(std::move(rules), ctx);
    Mutator mutator(ctx);
    FTester tester = [](TreeMutation& tree_mut, std::unordered_set<size_t>&,
                        Context& ctx) -> bool {
      if (tree_mut.UnparseToVec(ctx).find("a1") != std::string::npos) {
        return true;
      } else {
        return false;
      }
    };

    std::unordered_set<size_t> bits;
    mutator.MinimizeTree(tree, bits, ctx, 0, tree.Size(), tester);

    std::string unparse = tree.UnparseToVec(ctx);
    BOOST_CHECK(unparse.find("a1") != std::string::npos);
    BOOST_CHECK(unparse.find("a2") == std::string::npos);
    BOOST_CHECK(unparse.find("b2") == std::string::npos);
    BOOST_CHECK(unparse.find("b3") == std::string::npos);
  }
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecMutatorMinimizeRec) {
  Context ctx;
  RuleID r1 = ctx.AddRule("S", "s1 {A}");
  ctx.AddRule("S", "s2");
  RuleID r2 = ctx.AddRule("A", "a1 {B}");
  ctx.AddRule("A", "a1");
  ctx.AddRule("A", "a2");
  RuleID r3 = ctx.AddRule("B", "b1");
  ctx.AddRule("B", "b2");
  ctx.AddRule("B", "b3{B}");
  ctx.Initialize(10);

  for (size_t i = 0; i < 100; i++) {
    std::vector<RuleIDOrCustom> rules{RuleIDOrCustom(r1), RuleIDOrCustom(r2),
                                      RuleIDOrCustom(r3)};
    Tree tree(std::move(rules), ctx);
    Mutator mutator(ctx);
    FTester tester = [](TreeMutation& tree_mut, std::unordered_set<size_t>&,
                        Context& ctx) -> bool {
      if (tree_mut.UnparseToVec(ctx).find("a1") != std::string::npos) {
        return true;
      } else {
        return false;
      }
    };

    std::unordered_set<size_t> bits;
    mutator.MinimizeRec(tree, bits, ctx, 0, tree.Size(), tester);

    std::string unparse = tree.UnparseToVec(ctx);
    BOOST_CHECK(unparse.find("a1") != std::string::npos);
    BOOST_CHECK(unparse.find("a2") == std::string::npos);
    BOOST_CHECK(unparse.find("b2") == std::string::npos);
    BOOST_CHECK(unparse.find("b3") == std::string::npos);
  }
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecMutatorDeterministicRule) {
  Context ctx;
  RuleID r1 = ctx.AddRule("A", "a {A:a}");
  ctx.AddRule("A", "b {A:a}");
  ctx.AddRule("A", "a");
  ctx.Initialize(101);

  for (size_t i = 0; i < 100; i++) {
    Tree tree = ctx.GenerateTreeFromRule(r1, 100);
    Mutator mutator(ctx);
    std::string unparse = tree.UnparseToVec(ctx);
    size_t count = 0;

    FTesterMut tester = [&count, &unparse](TreeMutation& tree_mut,
                                           Context& ctx) {
      BOOST_CHECK(tree_mut.UnparseToVec(ctx) != unparse);
      count++;
    };

    mutator.MutRules(tree, ctx, 0, tree.Size(), tester);
    BOOST_CHECK(count > 2);
  }
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecMutatorDeterministicSplice) {
  Context ctx;
  fs::create_directories("/tmp/nautilus/chunks");

  ChunkStore cks("/tmp/nautilus");
  RuleID r1 = ctx.AddRule("A", "a {A:a}");
  ctx.AddRule("A", "b {A:a}");
  RuleID r3 = ctx.AddRule("A", "c {A:a}");
  ctx.AddRule("A", "a");
  ctx.Initialize(101);

  Tree tree = ctx.GenerateTreeFromRule(r3, 100);
  cks.AddTree(tree, ctx);

  for (size_t i = 0; i < 100; i++) {
    Tree tree = ctx.GenerateTreeFromRule(r1, 100);
    Mutator mutator(ctx);
    std::string unparse = tree.UnparseToVec(ctx);

    FTesterMut tester = [&unparse](TreeMutation& tree_mut, Context& ctx) {
      BOOST_CHECK(tree_mut.UnparseToVec(ctx) != unparse);
    };

    mutator.MutSplice(tree, ctx, cks, tester);
  }
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecMutatorDetRulesValues) {
  Context ctx;
  RuleID r1 = ctx.AddRule("S", "s1 {A}");
  ctx.AddRule("S", "s2 {A}");
  RuleID r2 = ctx.AddRule("A", "a1 {B}");
  ctx.AddRule("A", "a2 {B}");
  RuleID r3 = ctx.AddRule("B", "b1");
  ctx.AddRule("B", "b2");
  ctx.Initialize(10);

  for (size_t i = 0; i < 100; i++) {
    std::vector<RuleIDOrCustom> rules{RuleIDOrCustom(r1), RuleIDOrCustom(r2),
                                      RuleIDOrCustom(r3)};
    Tree tree(std::move(rules), ctx);
    Mutator mutator(ctx);
    std::unordered_set<std::string> unparses;

    FTesterMut tester = [&unparses](TreeMutation& tree_mut, Context& ctx) {
      unparses.insert(tree_mut.UnparseToVec(ctx));
    };

    mutator.MutRules(tree, ctx, 0, tree.Size(), tester);

    BOOST_CHECK(unparses.find("s1 a1 b2") != unparses.end());
    BOOST_CHECK(unparses.find("s1 a2 b1") != unparses.end() ||
                unparses.find("s1 a2 b2") != unparses.end());
    BOOST_CHECK(unparses.find("s2 a1 b1") != unparses.end() ||
                unparses.find("s2 a2 b2") != unparses.end() ||
                unparses.find("s2 a1 b2") != unparses.end() ||
                unparses.find("s2 a2 b1") != unparses.end());
  }
}
