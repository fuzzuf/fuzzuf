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
#define BOOST_TEST_MODULE nautilus.tree
#define BOOST_TEST_DYN_LINK

#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"

#include <boost/test/unit_test.hpp>
#include <vector>

#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"

using namespace fuzzuf::algorithm::nautilus::grammartec;

size_t CalcSubTreeSizesAndParentsRecTest(Tree& tree, const NodeID& n,
                                         Context& ctx) {
  NodeID cur(n + 1);
  size_t size = 1;
  size_t iter_n = tree.GetRule(n, ctx).NumberOfNonterms();

  for (size_t i = 0; i < iter_n; i++) {
    tree.paren()[static_cast<size_t>(cur)] = n;
    size_t sub_size = CalcSubTreeSizesAndParentsRecTest(tree, cur, ctx);
    cur = cur + sub_size;
    size += sub_size;
  }

  tree.sizes()[static_cast<size_t>(n)] = size;
  return size;
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecTreeCalcSizesIter) {
  Context ctx;
  ctx.AddRule("C", "c{B}c3");
  ctx.AddRule("B", "b{A}b23");
  ctx.AddRule("A", "aasdf {A}");
  ctx.AddRule("A", "a2 {A}");
  ctx.AddRule("A", "a sdf{A}");
  ctx.AddRule("A", "a 34{A}");
  ctx.AddRule("A", "adfe {A}");
  ctx.AddRule("A", "adfe {A}");
  ctx.AddRule("A", "a32");
  ctx.Initialize(50);
  Tree tree({}, ctx);

  for (size_t i = 0; i < 100; i++) {
    tree.Truncate();
    tree.GenerateFromNT(ctx.NTID("C"), 50, ctx);
    CalcSubTreeSizesAndParentsRecTest(tree, NodeID(0), ctx);

    std::vector<size_t>& vec1 = tree.sizes();
    tree.CalcSizes();
    std::vector<size_t>& vec2 = tree.sizes();
    BOOST_CHECK(vec1 == vec2);
  }
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecTreeCalcParenIter) {
  Context ctx;
  ctx.AddRule("C", "c{B}c3");
  ctx.AddRule("B", "b{A}b23");
  ctx.AddRule("A", "aasdf {A}");
  ctx.AddRule("A", "a2 {A}");
  ctx.AddRule("A", "a sdf{A}");
  ctx.AddRule("A", "a 34{A}");
  ctx.AddRule("A", "adfe {A}");
  ctx.AddRule("A", "adfe {A}");
  ctx.AddRule("A", "a32");
  ctx.Initialize(50);
  Tree tree({}, ctx);

  for (size_t i = 0; i < 100; i++) {
    tree.Truncate();
    tree.GenerateFromNT(ctx.NTID("C"), 50, ctx);
    CalcSubTreeSizesAndParentsRecTest(tree, NodeID(0), ctx);

    std::vector<NodeID>& vec1 = tree.paren();
    tree.CalcParents(ctx);
    std::vector<NodeID>& vec2 = tree.paren();
    BOOST_CHECK(vec1 == vec2);
  }
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecTreeUnparseIter) {
  Context ctx;
  ctx.AddRule("C", "c{B}c3");
  ctx.AddRule("B", "b{A}b23");
  ctx.AddRule("A", "aasdf {A}");
  ctx.AddRule("A", "a2 {A}");
  ctx.AddRule("A", "a sdf{A}");
  ctx.AddRule("A", "a 34{A}");
  ctx.AddRule("A", "adfe {A}");
  ctx.AddRule("A", "adfe {A}");
  ctx.AddRule("A", "a32");
  ctx.Initialize(50);
  Tree tree({}, ctx);

  for (size_t i = 0; i < 100; i++) {
    tree.Truncate();
    tree.GenerateFromNT(ctx.NTID("C"), 50, ctx);

    std::string s1, s2;
    tree.Unparse(NodeID(0), ctx, s1);
    tree.Unparse(NodeID(0), ctx, s2);
    BOOST_CHECK(s1 == s2);
  }
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecTreeFindRecursions) {
  Context ctx;
  ctx.AddRule("C", "c{B}c");
  ctx.AddRule("B", "b{A}b");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a");
  ctx.Initialize(20);
  Tree tree({}, ctx);
  bool some_recursion = false;

  for (size_t i = 0; i < 100; i++) {
    tree.Truncate();
    tree.GenerateFromNT(ctx.NTID("C"), 20, ctx);

    if (auto recursions = tree.CalcRecursions(ctx)) {
      BOOST_CHECK(recursions.value().size() != 0);

      for (RecursionInfo& recursion_info : recursions.value()) {
        for (size_t offset = 0; offset < recursion_info.GetNumberOfRecursions();
             offset++) {
          std::pair<NodeID, NodeID> tuple =
              recursion_info.GetRecursionPairByOffset(offset);
          some_recursion = true;

          BOOST_CHECK(static_cast<size_t>(tuple.first) <
                      static_cast<size_t>(tuple.second));
        }
      }
    }
  }

  BOOST_CHECK(some_recursion);
}
