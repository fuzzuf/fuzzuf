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

// In this test, simple type and routine are enough.
using VoidType = void(void);

// This routine just adds its name to a record when executed.
// The record will be used to check the order of executed nodes.
struct VoidRoutine
    : public fuzzuf::hierarflow::HierarFlowRoutine<VoidType, VoidType> {
  VoidRoutine(std::string name, std::vector<std::string>& order_queue)
      : name(name), order_queue(order_queue) {}

  fuzzuf::utils::NullableRef<fuzzuf::hierarflow::HierarFlowCallee<VoidType>>
  operator()(void) {
    order_queue.emplace_back(name);
    CallSuccessors();
    return GoToDefaultNext();
  }

  std::string name;
  std::vector<std::string>& order_queue;
};

// The following testcase intentionally causes a memory leak.
// We need to disable AddressSanitizer's leak detection.
extern "C" const char* __asan_default_options() { return "detect_leaks=0"; }

/**
 * Check if HierarFlow operators can handle all the known corner cases.
 * Some of the corner cases can cause an infinite loop, so this function has a
 * time limit.
 */
BOOST_AUTO_TEST_CASE(CheckCornerCaseHandling, *boost::unit_test::timeout(5)) {
  using fuzzuf::hierarflow::CreateIrregularNode;
  using fuzzuf::hierarflow::CreateNode;

  // Case 1. "auto a = CreateNode<SomeRoutine>(); a << a.HardLink();"
  // Because HierarFlowRoutine and HierarFlowNode are separated,
  // HierarFlowNode::operator() sets the reference of node that is currently
  // executed(that is, "this") to a routine instance. Otherwise, the routine
  // cannot know the successors or the parent of th executed node. This means
  // HierarFlowNode::operator must save the reference of node that is previously
  // set to the routine before setting the new one if the same routine is used
  // in different nodes. Otherwise, the routine forgets what was set before and
  // becomes unable to jump to the next node properly.
  {
    std::vector<std::string> order;
    auto a = CreateNode<VoidRoutine>("a", order);
    auto b = CreateNode<VoidRoutine>("b", order);
    auto c = CreateNode<VoidRoutine>("c", order);
    auto d = CreateNode<VoidRoutine>("d", order);

    a << (a.HardLink() << a.HardLink() << (b || c) || d);
    a();

    std::vector<std::string> expected{"a", "a", "a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // Case 2. "auto a = CreateNode<Routine<X, Y>>(); auto y =
  // CreateNode<Routine<Y, X>>(); a << b; b << a;" In the current specification,
  // cycles are prohibited.
  {
    // Bad practice, but needed: this case creates a circular reference, which
    // results in memory leak. So let's tell boost to ignore the memory leak.
    char env[] = "BOOST_TEST_DETECT_MEMORY_LEAK=0";
    putenv(env);

    std::vector<std::string> order;
    auto a = CreateNode<VoidRoutine>("a", order);
    auto b = CreateNode<VoidRoutine>("b", order);

    a << b;
    BOOST_CHECK_THROW(b << a, fuzzuf::exceptions::wrong_hierarflow_usage);
  }
}
