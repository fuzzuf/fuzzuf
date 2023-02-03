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
#ifndef FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_CHILDREN_HPP
#define FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_CHILDREN_HPP

#include <memory>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_node_impl.hpp"
#include "fuzzuf/hierarflow/hierarflow_path.hpp"

namespace fuzzuf::hierarflow {

// The class which describes a sequence of child nodes like `a || b || c`
template <class I, class HeadO, class TailO>
class HierarFlowChildren {
  template <class A, class B, bool C>
  friend class HierarFlowNode;

  template <class A, class B, class C, class D, bool E>
  friend class HierarFlowPath;

  template <class A, class B, class C>
  friend class HierarFlowChildren;

 public:
  // Valid HierarFlowChildren instances always have non-empty `this->children`.
  // Therefore, if it's empty, that means the instance has been invalidated.
  bool IsInvalidInstance() { return children.empty(); }

  template <class O, bool IS_NODE_REGULAR>
  HierarFlowChildren<I, HeadO, O> operator||(
      HierarFlowNode<I, O, IS_NODE_REGULAR> new_last) {
    // children will be invalidated
    return MoveChildrenWithNewTail(new_last.impl);
  }

  template <class A, class B, class C, bool IS_PATH_REGULAR>
  HierarFlowChildren<I, HeadO, A> operator||(
      HierarFlowPath<I, A, B, C, IS_PATH_REGULAR> path) {
    // children will be invalidated
    return MoveChildrenWithNewTail(path.head);
  }

  template <class O, class O2>
  HierarFlowChildren<I, HeadO, O2> operator||(
      HierarFlowChildren<I, O, O2> subsequent) {
    // Invalid instances should never be used.
    if (IsInvalidInstance() || subsequent.IsInvalidInstance()) {
      throw exceptions::wrong_hierarflow_usage(
          "This HierarFlowChildren instance has been invalidated before.\n"
          "You should never use HierarFlowChildren instances twice by saving "
          "it as a variable.\n"
          "For example, `auto children = (a || b); c << (children || d); e << "
          "(children || e);` doesn't make sense.",
          __FILE__, __LINE__);
    }

    // We must move children and subsequent.children to a new HierarFlowChildren
    // instance. For example, the following series of operations is definitely
    // invalid: `auto base_chain = (a || b); auto chain1 = (base_chain || c);
    // auto chain2 = (base_chain || d);`

    // Not to leave children as a "moved-from" object, swap it with a empty
    // vector first.
    std::vector<std::shared_ptr<HierarFlowCallee<I>>> tmp;
    tmp.swap(children);

    tmp.insert(tmp.end(), std::make_move_iterator(subsequent.children.begin()),
               std::make_move_iterator(subsequent.children.end()));
    subsequent.children.clear();

    return HierarFlowChildren<I, HeadO, O2>(std::move(tmp), first_child);
  }

 private:
  HierarFlowChildren(std::shared_ptr<HierarFlowNodeImpl<I, HeadO>> one,
                     std::shared_ptr<HierarFlowNodeImpl<I, TailO>> two)
      : children{one, two}, first_child(*one) {}

  HierarFlowChildren(
      std::vector<std::shared_ptr<HierarFlowCallee<I>>> &&initial_children,
      HierarFlowNodeImpl<I, HeadO> &first_child)
      : children(std::move(initial_children)), first_child(first_child) {}

  template <class O>
  HierarFlowChildren<I, HeadO, O> MoveChildrenWithNewTail(
      std::shared_ptr<HierarFlowNodeImpl<I, O>> child) {
    // Invalid instances should never be used.
    if (IsInvalidInstance()) {
      throw exceptions::wrong_hierarflow_usage(
          "This HierarFlowChildren instance has been invalidated before.\n"
          "You should never use HierarFlowChildren instances twice by saving "
          "it as a variable.\n"
          "For example, `auto children = (a || b); c << (children || d); e << "
          "(children || e);` doesn't make sense.",
          __FILE__, __LINE__);
    }

    // We don't move new_last.impl from new_last to this instance.
    // Consider the following series of operations: `root << (a || b); b << c;`
    children.emplace_back(child);

    // On the contrary, we must move children to a new HierarFlowChildren
    // instance. For example, the following series of operations is definitely
    // invalid: `auto base_chain = (a || b); auto chain1 = (base_chain || c);
    // auto chain2 = (base_chain || d);`

    // Not to leave children as a "moved-from" object, swap it with a empty
    // vector first.
    std::vector<std::shared_ptr<HierarFlowCallee<I>>> tmp;
    tmp.swap(children);
    return HierarFlowChildren<I, HeadO, O>(std::move(tmp), first_child);
  }

  std::vector<std::shared_ptr<HierarFlowCallee<I>>> children;
  // FIXME: remove first_child when it becomes unnecessary
  HierarFlowNodeImpl<I, HeadO> &first_child;
};

}  // namespace fuzzuf::hierarflow

#endif
