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
#define BOOST_TEST_MODULE nautilus.newtypes
#define BOOST_TEST_DYN_LINK

#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"

#include <boost/range/irange.hpp>
#include <boost/test/unit_test.hpp>

using namespace fuzzuf::algorithm::nautilus::grammartec;

BOOST_AUTO_TEST_CASE(NautilusGrammartecNewtypesRuleID) {
  RuleID r1 = 1337;
  RuleID r2(1338);
  size_t i1 = static_cast<size_t>(r1);
  BOOST_CHECK_EQUAL(i1, 1337);
  size_t i2 = 1338;
  BOOST_CHECK_EQUAL(i2, static_cast<size_t>(r2));
  RuleID r3 = r2 + 3;
  BOOST_CHECK_EQUAL(static_cast<size_t>(r3), 1341);
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecNewtypesNodeID) {
  NodeID r1 = 1337;
  NodeID r2(1338);
  size_t i1 = static_cast<size_t>(r1);
  BOOST_CHECK_EQUAL(i1, 1337);
  size_t i2 = 1338;
  BOOST_CHECK_EQUAL(i2, static_cast<size_t>(r2));
  NodeID r3 = r2 + 3;
  BOOST_CHECK_EQUAL(static_cast<size_t>(r3), 1341);
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecNewtypesNTermID) {
  NTermID r1 = 1337;
  NTermID r2(1338);
  size_t i1 = static_cast<size_t>(r1);
  BOOST_CHECK_EQUAL(i1, 1337);
  size_t i2 = 1338;
  BOOST_CHECK_EQUAL(i2, static_cast<size_t>(r2));
  NodeID r3 = r2 + 3;
  BOOST_CHECK_EQUAL(static_cast<size_t>(r3), 1341);
}

BOOST_AUTO_TEST_CASE(NautilusGrammartecNewtypesNodeIDStepImpl) {
  size_t x = 1337;
  size_t y = 1360;
  NodeID r1 = x;
  NodeID r2(y);
  size_t sum_from_nodes = 0;
  for (auto node : boost::irange(r1, r2)) {
    sum_from_nodes += node;
  }
  size_t sum_from_ints = 0;
  for (auto i : boost::irange(x, y)) {
    sum_from_ints += i;
  }
  BOOST_CHECK_EQUAL(sum_from_nodes, sum_from_ints);
}
