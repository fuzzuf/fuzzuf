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
#define BOOST_TEST_MODULE hierarflow.handle_corner_cases
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <optional>
#include <random>
#include <type_traits>

#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

// In this test, we want to test response values are correctly set
using IntType = int(int);

// This routine adds its name to a record and sets an integer as a response
// value when executed. The record will be used to check the order of executed
// nodes.
struct IntRoutine
    : public fuzzuf::hierarflow::HierarFlowRoutine<IntType, IntType> {
  IntRoutine(std::string name, std::vector<std::string>& order_queue)
      : name(name), order_queue(order_queue) {}

  fuzzuf::utils::NullableRef<fuzzuf::hierarflow::HierarFlowCallee<IntType>>
  operator()(int arg) {
    order_queue.emplace_back(name);
    int res = CallSuccessors(arg);
    SetResponseValue(res);
    return GoToDefaultNext();
  }

  std::string name;
  std::vector<std::string>& order_queue;
};

// This routine adds its name to a record, sets an integer as a response value,
// and returns to its parent when executed. The record will be used to check the
// order of executed nodes.
struct IntGoToParentRoutine
    : public fuzzuf::hierarflow::HierarFlowRoutine<IntType, IntType> {
  IntGoToParentRoutine(std::string name, std::vector<std::string>& order_queue)
      : name(name), order_queue(order_queue) {}

  fuzzuf::utils::NullableRef<fuzzuf::hierarflow::HierarFlowCallee<IntType>>
  operator()(int arg) {
    order_queue.emplace_back(name);
    SetResponseValue(arg);
    return GoToParent();
  }

  std::string name;
  std::vector<std::string>& order_queue;
};

/**
 * Test CallRandomChild works intendedly to some extent.
 *
 * @todo Because we haven't unify the designs of random number generator and
 * distribution, currently we cannot force it to behave deterministically.
 * Therefore, this function doesn't test if CallRandomChild actually calls
 * children uniformly randomly. For the time being, the function only ensures
 * that CallRandomChild calls exactly one child.
 */
BOOST_AUTO_TEST_CASE(TestCallRandomChild) {
  using fuzzuf::hierarflow::CallRandomChild;
  using fuzzuf::hierarflow::CreateIrregularNode;
  using fuzzuf::hierarflow::CreateNode;
  using fuzzuf::hierarflow::WrapToMakeHeadNode;

  for (int i = 0; i < 50; i++) {
    std::vector<std::string> order;
    auto random = CreateIrregularNode<CallRandomChild<IntType>>();
    auto a = CreateNode<IntRoutine>("a", order);
    auto b = CreateNode<IntRoutine>("b", order);
    auto c = CreateNode<IntRoutine>("c", order);
    auto d = CreateNode<IntRoutine>("d", order);

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-comparison"
#endif
    random <= (a || b || c || d);
#ifdef __clang__
#pragma GCC diagnostic pop
#endif
    WrapToMakeHeadNode(random)(0);

    BOOST_CHECK_EQUAL(order.size(), 1);
    if (order.size() >= 1) {
      BOOST_CHECK(order[0] == "a" || order[0] == "b" || order[0] == "c" ||
                  order[0] == "d");
    }
  }
}

/**
 * Test Finally works intendedly. This function tests check if the node that
 * works as a "finally" block is always executed. The function defines two
 * different flows and check it in both.
 */
BOOST_AUTO_TEST_CASE(TestFinally) {
  using fuzzuf::hierarflow::CreateNode;
  using fuzzuf::hierarflow::Finally;
  using fuzzuf::hierarflow::WrapToMakeHeadNode;

  // Case 1. simply every node is executed.
  {
    std::vector<std::string> order;
    auto a = CreateNode<IntRoutine>("a", order);
    auto b = CreateNode<IntRoutine>("b", order);
    auto c = CreateNode<IntRoutine>("c", order);
    auto d = CreateNode<IntRoutine>("d", order);
    auto e = CreateNode<IntRoutine>("e", order);

    a << Finally(e) << (b || c || d);
    WrapToMakeHeadNode(a)(0);

    std::vector<std::string> expected{"a", "b", "c", "d", "e"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // Case 2. suddenly some node uses GoToParent()
  {
    std::vector<std::string> order;
    auto a = CreateNode<IntRoutine>("a", order);
    auto b = CreateNode<IntRoutine>("b", order);
    auto c = CreateNode<IntGoToParentRoutine>("c", order);
    auto d = CreateNode<IntRoutine>("d", order);
    auto e = CreateNode<IntRoutine>("e", order);

    a << Finally(e) << (b || c || d);
    WrapToMakeHeadNode(a)(1);

    // "d" won't be executed.
    std::vector<std::string> expected{"a", "b", "c", "e"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }
}
