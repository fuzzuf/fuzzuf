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
#define BOOST_TEST_MODULE nautilus.context
#define BOOST_TEST_DYN_LINK

#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"

#include <boost/test/unit_test.hpp>
#include <vector>

#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"

using namespace fuzzuf::algorithm::nautilus::grammartec;

BOOST_AUTO_TEST_CASE(NautilusGrammartecContextSimple) {
  Context ctx;
  Rule r(ctx, "F", "foo{A:a}\\{bar\\}{B:b}asd{C}");
  std::vector<RuleChild> soll{RuleChild("foo"),   RuleChild("{A:a}", ctx),
                              RuleChild("{bar}"), RuleChild("{B:b}", ctx),
                              RuleChild("asd"),   RuleChild("{C}", ctx)};
  BOOST_CHECK_EQUAL(std::holds_alternative<PlainRule>(r.value()), true);

  const PlainRule& rl = std::get<PlainRule>(r.value());
  BOOST_CHECK(rl.children == soll);
  BOOST_CHECK(r.Nonterms()[0] == ctx.NTID("A"));
  BOOST_CHECK(r.Nonterms()[1] == ctx.NTID("B"));
  BOOST_CHECK(r.Nonterms()[2] == ctx.NTID("C"));
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecContext) {
  Context ctx;
  const RuleID& r0 = ctx.AddRule("C", "c{B}c");
  const RuleID& r1 = ctx.AddRule("B", "b{A}b");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a {A}");
  ctx.AddRule("A", "a {A}");
  const RuleID& r3 = ctx.AddRule("A", "a");
  ctx.Initialize(5);

  BOOST_CHECK_EQUAL(ctx.GetMinLenForNT(ctx.NTID("A")), 1);
  BOOST_CHECK_EQUAL(ctx.GetMinLenForNT(ctx.NTID("B")), 2);
  BOOST_CHECK_EQUAL(ctx.GetMinLenForNT(ctx.NTID("C")), 3);

  Tree tree({}, ctx);
  tree.GenerateFromNT(ctx.NTID("C"), 3, ctx);
  std::vector<RuleIDOrCustom> trules{RuleIDOrCustom(r0), RuleIDOrCustom(r1),
                                     RuleIDOrCustom(r3)};
  BOOST_CHECK(tree.rules() == trules);
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecGenerateLen) {
  Context ctx;
  const RuleID& r0 = ctx.AddRule("E", "({E}+{E})");
  const RuleID& r1 = ctx.AddRule("E", "({E}*{E})");
  const RuleID& r2 = ctx.AddRule("E", "({E}-{E})");
  const RuleID& r3 = ctx.AddRule("E", "({E}/{E})");
  const RuleID& r4 = ctx.AddRule("E", "1");
  ctx.Initialize(11);
  BOOST_CHECK_EQUAL(ctx.GetMinLenForNT(ctx.NTID("E")), 1);

  for (size_t i = 0; i < 100; i++) {
    Tree tree({}, ctx);
    tree.GenerateFromNT(ctx.NTID("E"), 9, ctx);
    BOOST_CHECK(tree.rules().size() < 10);
    BOOST_CHECK(tree.rules().size() >= 1);
  }

  std::vector<RuleIDOrCustom> rules{RuleIDOrCustom(r0), RuleIDOrCustom(r1),
                                    RuleIDOrCustom(r4), RuleIDOrCustom(r4),
                                    RuleIDOrCustom(r4)};
  Tree tree(std::move(rules), ctx);
  std::string data;
  tree.UnparseTo(ctx, data);
  BOOST_CHECK_EQUAL(data, "((1*1)+1)");

  rules = {RuleIDOrCustom(r0), RuleIDOrCustom(r1), RuleIDOrCustom(r2),
           RuleIDOrCustom(r3), RuleIDOrCustom(r4), RuleIDOrCustom(r4),
           RuleIDOrCustom(r4), RuleIDOrCustom(r4), RuleIDOrCustom(r4)};
  tree = Tree(std::move(rules), ctx);
  data = "";
  tree.UnparseTo(ctx, data);
  BOOST_CHECK_EQUAL(data, "((((1/1)-1)*1)+1)");
}
