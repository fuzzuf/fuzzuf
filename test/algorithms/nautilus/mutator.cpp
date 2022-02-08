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
#define BOOST_TEST_MODULE nautilus.mutator
#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>
#include "fuzzuf/algorithms/nautilus/grammartec/mutator.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"


using namespace fuzzuf::algorithms::nautilus::grammartec;

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

  std::vector<RuleIDOrCustom> rules = {
    RuleIDOrCustom(r1), RuleIDOrCustom(r2), RuleIDOrCustom(r3),
    RuleIDOrCustom(r4), RuleIDOrCustom(r5),
  };
  Tree tree(rules, ctx);

  Mutator mutator(ctx);
  FTesterMut tester =
    [&r1, &r2, &r3, &r4, &r5](TreeMutation& tree_mut, Context &) {
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
