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

#include "fuzzuf/algorithms/nautilus/grammartec/chunkstore.hpp"

#include <boost/test/unit_test.hpp>

#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/utils/filesystem.hpp"

using namespace fuzzuf::algorithm::nautilus::grammartec;

BOOST_AUTO_TEST_CASE(NautilusGrammartecChunkstore) {
  Context ctx;
  RuleID r1 = ctx.AddRule("A", "a {B:a}");
  RuleID r2 = ctx.AddRule("B", "b {C:a}");
  ctx.AddRule("C", "c");
  ctx.Initialize(101);

  size_t random_size = ctx.GetRandomLenForRuleID(r1);
  Tree tree = ctx.GenerateTreeFromRule(r1, random_size);
  fs::create_directories("/tmp/nautilus/chunks");

  ChunkStore cks("/tmp/nautilus");
  cks.AddTree(tree, ctx);

  BOOST_CHECK(cks.seen_outputs().find("a b c") != cks.seen_outputs().end());
  BOOST_CHECK(cks.seen_outputs().find("b c") != cks.seen_outputs().end());
  BOOST_CHECK(cks.seen_outputs().find("c") != cks.seen_outputs().end());
  BOOST_CHECK_EQUAL(cks.nts_to_chunks().at(ctx.NTID("A")).size(), 1);
  auto& [tid, _] = cks.nts_to_chunks().at(ctx.NTID("A")).at(0);
  BOOST_CHECK_EQUAL(cks.trees().at(tid).UnparseToVec(ctx), "a b c");
  (void)_;

  random_size = ctx.GetRandomLenForRuleID(r2);
  tree = ctx.GenerateTreeFromRule(r2, random_size);
  cks.AddTree(tree, ctx);

  BOOST_CHECK_EQUAL(cks.seen_outputs().size(), 3);
  BOOST_CHECK_EQUAL(cks.nts_to_chunks().at(ctx.NTID("B")).size(), 1);
  auto& [tree_id, node_id] = cks.nts_to_chunks().at(ctx.NTID("B")).at(0);
  BOOST_CHECK_EQUAL(cks.trees().at(tree_id).UnparseNodeToVec(node_id, ctx),
                    "b c");
}
