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
#define BOOST_TEST_MODULE hierarflow.check_operator_behavior
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

// In the following tests, we use only these types in HierarFlowNode.
// The root node should derive HierarFlowRoutine<TypeLevel1, TypeLevel2>, and
// its children should derive HierarFlowRoutine<TypeLevel2, TypeLevel3>, and so
// on.
using TypeLevel1 = void(void);
using TypeLevel2 = int(char);
using TypeLevel3 = short(int, int, int);
using TypeLevel4 = char(short, short);
using TypeLevel5 = std::string(std::string);

// To define similar routines multiple times, we use the following macro.
// The constructor of defined routines has two arguments that are used to record
// the order of executed nodes.
#define DEFINE_ROUTINE(level_n_1, level_n, ArgumentType, RetType, ...) \
  struct Routine##level_n_1                                            \
      : public fuzzuf::hierarflow::HierarFlowRoutine<Type##level_n_1,  \
                                                     Type##level_n> {  \
    Routine##level_n_1(std::string name,                               \
                       std::vector<std::string>& order_queue)          \
        : name(name), order_queue(order_queue) {}                      \
                                                                       \
    fuzzuf::utils::NullableRef<                                        \
        fuzzuf::hierarflow::HierarFlowCallee<Type##level_n_1>>         \
    operator() ArgumentType {                                          \
      order_queue.emplace_back(name);                                  \
      RetType ret = CallSuccessors(__VA_ARGS__);                       \
      (void)ret; /* to avoid -Wunused-parameter */                     \
      return GoToDefaultNext();                                        \
    }                                                                  \
                                                                       \
    std::string name;                                                  \
    std::vector<std::string>& order_queue;                             \
  }

DEFINE_ROUTINE(Level1, Level2, (void), int, 'a');
DEFINE_ROUTINE(Level2, Level3, (char), short, 1, 2, 3);
DEFINE_ROUTINE(Level3, Level4, (int, int, int), char, 1, 2);
DEFINE_ROUTINE(Level4, Level5, (short, short), std::string, "hello");

/**
 * Check all the defined operators.
 * In the HierarFlow definition, three types of values appear:
 *    node(HierarFlowNode), path(HierarFlowPath), ch(HierarFlowChildren).
 * For those types, the following operations are possible:
 *     1. node << node
 *     2. node [ node ]
 *     3. node <= node
 *     4. node || node
 *
 *     5. node << path
 *     6. node [ path ]
 *     7. node <= path
 *     8. node || path
 *
 *     9. node << ch
 *    10. node [ ch ]
 *    11. node <= ch
 *    12. node || ch
 *
 *    13. path << node
 *    14. path [ node ]
 *    15. path <= node
 *    16. path || node
 *
 *    17. path << path
 *    18. path [ path ]
 *    19. path <= path
 *    20. path || path
 *
 *    21. path << ch
 *    22. path [ ch ]
 *    23. path <= ch
 *    24. path || ch
 *
 *    25. ch || node
 *
 *    26. ch || path
 *
 * This function checks these 26 patterns by actually evaluating each operation
 * and executing the resultant flows. For operator||, it additionally creates a
 * root node and connects it with the target HierarFlowChildren instance because
 * otherwise HierarFlowChildren cannot be executed alone. We assume an operator
 * works correctly if the order of executed nodes is correct and no crash
 * occurs.
 */
BOOST_AUTO_TEST_CASE(CheckAllPatternsOfOperatorUsage) {
  using fuzzuf::hierarflow::CreateIrregularNode;
  using fuzzuf::hierarflow::CreateNode;

  // 1. node << node
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);

    a << b;
    a();

    std::vector<std::string> expected{"a", "b"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 2. node [ node ]
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);

    a[b];
    a();

    std::vector<std::string> expected{"a", "b"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 3. node <= node
  {
    std::vector<std::string> order;
    auto a = CreateIrregularNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-comparison"
#endif
    a <= b;
#ifdef __clang__
#pragma GCC diagnostic pop
#endif
    a();

    std::vector<std::string> expected{"a", "b"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 4. node || node
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);

    a << (b || c);
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 5. node << path
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto path = b << c;

    a << path;
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 6. node [ path ]
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto path = b << c;

    a[path];
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 7. node <= path
  {
    std::vector<std::string> order;
    auto a = CreateIrregularNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto path = b << c;

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-comparison"
#endif
    a <= path;
#ifdef __clang__
#pragma GCC diagnostic pop
#endif
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 8. node || path
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);
    auto d = CreateNode<RoutineLevel3>("d", order);
    auto path = c << d;

    a << (b || path);
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 9. node << ch
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);
    auto ch = b || c;

    a << ch;
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 10. node [ ch ]
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);
    auto ch = b || c;

    a[ch];
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 11. node <= ch
  {
    std::vector<std::string> order;
    auto a = CreateIrregularNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);
    auto ch = b || c;

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-comparison"
#endif
    a <= ch;
#ifdef __clang__
#pragma GCC diagnostic pop
#endif
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 12. node || ch
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);
    auto d = CreateNode<RoutineLevel2>("d", order);
    auto ch = c || d;

    a << (b || ch);
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 13. path << node
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto path = a << b;

    path << c;
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 14. path [ node ]
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto path = a << b;

    path << c;
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 15. path <= node
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateIrregularNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto path = a << b;

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-comparison"
#endif
    path <= c;
#ifdef __clang__
#pragma GCC diagnostic pop
#endif
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 16. path || node
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel2>("d", order);
    auto path = b << c;

    a << (path || d);
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 17. path << path
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel4>("d", order);
    auto path1 = a << b;
    auto path2 = c << d;

    path1 << path2;
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 18. path [ path ]
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel4>("d", order);
    auto path1 = a << b;
    auto path2 = c << d;

    path1[path2];
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 19. path <= path
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateIrregularNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel4>("d", order);
    auto path1 = a << b;
    auto path2 = c << d;

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-comparison"
#endif
    path1 <= path2;
#ifdef __clang__
#pragma GCC diagnostic pop
#endif
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 20. path || path
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel2>("d", order);
    auto e = CreateNode<RoutineLevel3>("e", order);
    auto path1 = b << c;
    auto path2 = d << e;

    a << (path1 || path2);
    a();

    std::vector<std::string> expected{"a", "b", "c", "d", "e"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 21. path << ch
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel3>("d", order);
    auto path = a << b;
    auto ch = c || d;

    path << ch;
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 22. path [ ch ]
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel3>("d", order);
    auto path = a << b;
    auto ch = c || d;

    path[ch];
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 23. path <= ch
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateIrregularNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel3>("d", order);
    auto path = a << b;
    auto ch = c || d;

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-comparison"
#endif
    path <= ch;
#ifdef __clang__
#pragma GCC diagnostic pop
#endif
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 24. path || ch
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);
    auto d = CreateNode<RoutineLevel2>("d", order);
    auto e = CreateNode<RoutineLevel2>("e", order);
    auto path = b << c;
    auto ch = d || e;

    a << (path || ch);
    a();

    std::vector<std::string> expected{"a", "b", "c", "d", "e"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 25. ch || node
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);
    auto d = CreateNode<RoutineLevel2>("d", order);
    auto ch = b || c;

    a << (ch || d);
    a();

    std::vector<std::string> expected{"a", "b", "c", "d"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // 26. ch || path
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);
    auto d = CreateNode<RoutineLevel2>("d", order);
    auto e = CreateNode<RoutineLevel3>("e", order);
    auto ch = b || c;
    auto path = d << e;

    a << (ch || path);
    a();

    std::vector<std::string> expected{"a", "b", "c", "d", "e"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }
}

/**
 * Check if other special behaviors occur as intended. Originally, those
 * behaviors were implementation-dependent and not specs. However, users tend to
 * think that those behaviors are specs, and the behaviors are not so weird in
 * fact. Therefore, we guarantee HierarFlow operators behave in those ways.
 */
BOOST_AUTO_TEST_CASE(CheckExtraPatterns) {
  using fuzzuf::hierarflow::CreateIrregularNode;
  using fuzzuf::hierarflow::CreateNode;

  // Case 1. `b << c; a << b;` must be the same as `a << b << c;`.
  // (operator<< must actually connect nodes when evaluated. It mustn't work
  // lazily.)
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);

    b << c;
    a << b;
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // Case 2. `a << b; a << c;` must be the same as `a << (b || c);`.
  // (The connected children must be preserved even if a new child is connected
  // later.
  //  In addition to that, the order of the children must be preserved.)
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel1>("a", order);
    auto b = CreateNode<RoutineLevel2>("b", order);
    auto c = CreateNode<RoutineLevel2>("c", order);

    a << b;
    a << c;
    a();

    std::vector<std::string> expected{"a", "b", "c"};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
  }

  // Case 3. every node mustn't be used in HierarFlowChildren more than once.
  // For example, `auto base_ch = a || b; auto ch1 = base_ch || c; auto ch2 =
  // base_ch || d` must be prohibited. Moreover, HierarFlowChildren instances
  // are invalidated when they are used to create a new instance. Invalid
  // instances should never be used thereafter. For example, `auto old_ch = a ||
  // b; auto new_ch = old_ch || c; root << old_ch` must be prohibited.
  {
    std::vector<std::string> order;
    auto a = CreateNode<RoutineLevel3>("a", order);
    auto b = CreateNode<RoutineLevel3>("b", order);
    auto c = CreateNode<RoutineLevel3>("c", order);

    // Create an invalid instance of HierarFlowChildren
    auto old_ch = a || b;
    auto new_ch = old_ch || c;  // Now, old_ch is invalidated.

    // All the following operations should throw errors.
    // Case 3.a. use operator|| with invalid children and a node.
    {
      auto node = CreateNode<RoutineLevel3>("node", order);
      BOOST_CHECK_THROW(old_ch || node,
                        fuzzuf::exceptions::wrong_hierarflow_usage);
      BOOST_CHECK_THROW(node || old_ch,
                        fuzzuf::exceptions::wrong_hierarflow_usage);
    }

    // Case 3.b. use operator|| with invalid children and a path.
    {
      auto x = CreateNode<RoutineLevel3>("x", order);
      auto y = CreateNode<RoutineLevel4>("y", order);
      auto path = x << y;
      BOOST_CHECK_THROW(old_ch || path,
                        fuzzuf::exceptions::wrong_hierarflow_usage);
      BOOST_CHECK_THROW(path || old_ch,
                        fuzzuf::exceptions::wrong_hierarflow_usage);
    }

    // Case 3.c. use operator|| with invalid children and another children.
    {
      auto x = CreateNode<RoutineLevel3>("x", order);
      auto y = CreateNode<RoutineLevel3>("y", order);
      auto ch = x || y;
      BOOST_CHECK_THROW(old_ch || ch,
                        fuzzuf::exceptions::wrong_hierarflow_usage);
      BOOST_CHECK_THROW(ch || old_ch,
                        fuzzuf::exceptions::wrong_hierarflow_usage);
    }

    // Case 3.d. use operator<< with invalid children and a node.
    {
      auto node = CreateNode<RoutineLevel2>("node", order);
      BOOST_CHECK_THROW(node << old_ch,
                        fuzzuf::exceptions::wrong_hierarflow_usage);
      // ch << something is not defined in the first place. So there's no need
      // to check.
    }

    // Case 3.e. use operator<< with invalid children and a path.
    {
      auto a = CreateNode<RoutineLevel1>("a", order);
      auto b = CreateNode<RoutineLevel2>("b", order);
      auto path = a << b;
      BOOST_CHECK_THROW(path << old_ch,
                        fuzzuf::exceptions::wrong_hierarflow_usage);
    }
  }
}
