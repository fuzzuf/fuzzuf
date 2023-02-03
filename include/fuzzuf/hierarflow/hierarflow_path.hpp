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
#ifndef FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_PATH_HPP
#define FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_PATH_HPP

#include <memory>

#include "fuzzuf/hierarflow/hierarflow_callee.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_node_impl.hpp"

namespace fuzzuf::hierarflow {

// Leave this as a incomplete type.
template <class I, class HeadO, class TailO>
class HierarFlowChildren;

// The class which describes a "chain" of nodes like `a << b << c`.

// IS_TAIL_REGULAR: describes the value "IS_REGULAR" of the tail node
// For the details, check the comments of HierarFlowNode.

template <class HeadI, class HeadO, class TailI, class TailO,
          bool IS_TAIL_REGULAR = true>
class HierarFlowPath {
  template <class A, class B, bool C>
  friend class HierarFlowNode;

  template <class A, class B, class C, class D, bool E>
  friend class HierarFlowPath;

  template <class A, class B, class C>
  friend class HierarFlowChildren;

 public:
  // operator<< should be defined only if IS_TAIL_REGULAR is true(SFINAE).
  template <class NewTailO, bool IS_NODE_REGULAR,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator<<(HierarFlowNode<TailO, NewTailO, IS_NODE_REGULAR> new_tail)
      -> std::enable_if_t<
          IS_TAIL_REGULAR_,
          HierarFlowPath<HeadI, HeadO, TailO, NewTailO, IS_NODE_REGULAR>> {
    tail.AddSuccessor(new_tail.impl);
    return HierarFlowPath<HeadI, HeadO, TailO, NewTailO, IS_NODE_REGULAR>(
        head, *new_tail.impl);
  }

  // operator[] should be defined only if IS_TAIL_REGULAR is true(SFINAE).
  template <class NewTailO, bool IS_NODE_REGULAR,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator[](HierarFlowNode<TailO, NewTailO, IS_NODE_REGULAR> new_tail)
      -> std::enable_if_t<
          IS_TAIL_REGULAR_,
          HierarFlowPath<HeadI, HeadO, TailO, NewTailO, IS_NODE_REGULAR>> {
    return this->operator<<(new_tail);
  }

  // operator<= should be defined only if IS_TAIL_REGULAR is false(SFINAE).
  template <class NewTailO, bool IS_NODE_REGULAR,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator<=(HierarFlowNode<TailO, NewTailO, IS_NODE_REGULAR> new_tail)
      -> std::enable_if_t<
          !IS_TAIL_REGULAR_,
          HierarFlowPath<HeadI, HeadO, TailO, NewTailO, IS_NODE_REGULAR>> {
    tail.AddSuccessor(new_tail.impl);
    return HierarFlowPath<HeadI, HeadO, TailO, NewTailO, IS_NODE_REGULAR>(
        head, *new_tail.impl);
  }

  // The followings are defined the same way using SFINAE

  template <class T, class NewTailI, class NewTailO, bool IS_PATH_REGULAR,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator<<(
      HierarFlowPath<TailO, T, NewTailI, NewTailO, IS_PATH_REGULAR> path)
      -> std::enable_if_t<
          IS_TAIL_REGULAR_,
          HierarFlowPath<HeadI, HeadO, NewTailI, NewTailO, IS_PATH_REGULAR>> {
    tail.AddSuccessor(path.head);
    return HierarFlowPath<HeadI, HeadO, NewTailI, NewTailO, IS_PATH_REGULAR>(
        head, path.tail);
  }

  template <class T, class NewTailI, class NewTailO, bool IS_PATH_REGULAR,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator[](
      HierarFlowPath<TailO, T, NewTailI, NewTailO, IS_PATH_REGULAR> path)
      -> std::enable_if_t<
          IS_TAIL_REGULAR_,
          HierarFlowPath<HeadI, HeadO, NewTailI, NewTailO, IS_PATH_REGULAR>> {
    return this->operator<<(path);
  }

  template <class T, class NewTailI, class NewTailO, bool IS_PATH_REGULAR,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator<=(
      HierarFlowPath<TailO, T, NewTailI, NewTailO, IS_PATH_REGULAR> path)
      -> std::enable_if_t<
          !IS_TAIL_REGULAR_,
          HierarFlowPath<HeadI, HeadO, NewTailI, NewTailO, IS_PATH_REGULAR>> {
    tail.AddSuccessor(path.head);
    return HierarFlowPath<HeadI, HeadO, NewTailI, NewTailO, IS_PATH_REGULAR>(
        head, path.tail);
  }

  // FIXME: Connecting nodes like `a << b << (c || d) << e` doesn't make any
  // sense. However, as you can see, this function allows such operations by
  // interpreting them like `a << b << (c << e || d)`. In the future, this
  // should be prohibited.
  template <class ChildHeadO, class ChildTailO,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator<<(HierarFlowChildren<TailO, ChildHeadO, ChildTailO> children)
      -> std::enable_if_t<IS_TAIL_REGULAR_, HierarFlowPath<HeadI, HeadO, TailO,
                                                           ChildHeadO, true>> {
    // If the given children is an invalid instance, throw an error.
    if (children.IsInvalidInstance()) {
      throw exceptions::wrong_hierarflow_usage(
          "This HierarFlowChildren instance has been invalidated before.\n"
          "You should never use HierarFlowChildren instances twice by saving "
          "it as a variable.\n"
          "For example, `auto children = (a || b); c << (children || d); e << "
          "(children || e);` doesn't make sense.",
          __FILE__, __LINE__);
    }

    tail.AddSuccessors(std::move(children.children));
    children.children.clear();

    return HierarFlowPath<HeadI, HeadO, TailO, ChildHeadO, true>(
        head, children.first_child);
  }

  template <class ChildHeadO, class ChildTailO,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator[](HierarFlowChildren<TailO, ChildHeadO, ChildTailO> children)
      -> std::enable_if_t<IS_TAIL_REGULAR_, HierarFlowPath<HeadI, HeadO, TailO,
                                                           ChildHeadO, true>> {
    // If the given children is an invalid instance, throw an error.
    if (children.IsInvalidInstance()) {
      throw exceptions::wrong_hierarflow_usage(
          "This HierarFlowChildren instance has been invalidated before.\n"
          "You should never use HierarFlowChildren instances twice by saving "
          "it as a variable.\n"
          "For example, `auto children = (a || b); c << (children || d); e << "
          "(children || e);` doesn't make sense.",
          __FILE__, __LINE__);
    }

    return this->operator<<(children);
  }

  template <class ChildHeadO, class ChildTailO,
            bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator<=(HierarFlowChildren<TailO, ChildHeadO, ChildTailO> children)
      -> std::enable_if_t<!IS_TAIL_REGULAR_, HierarFlowPath<HeadI, HeadO, TailO,
                                                            ChildHeadO, true>> {
    // If the given children is an invalid instance, throw an error.
    if (children.IsInvalidInstance()) {
      throw exceptions::wrong_hierarflow_usage(
          "This HierarFlowChildren instance has been invalidated before.\n"
          "You should never use HierarFlowChildren instances twice by saving "
          "it as a variable.\n"
          "For example, `auto children = (a || b); c << (children || d); e << "
          "(children || e);` doesn't make sense.",
          __FILE__, __LINE__);
    }

    tail.AddSuccessors(std::move(children.children));
    children.children.clear();

    return HierarFlowPath<HeadI, HeadO, TailO, ChildHeadO, true>(
        head, children.first_child);
  }

  // To emit human-readable compilation errors, we intentionally make
  // static_assert fail in prohibited(i.e. undefined in SFINAE) cases

  template <class... Args, bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator<<(Args...) -> std::enable_if_t<!IS_TAIL_REGULAR_, void> {
    static_assert(
        IS_TAIL_REGULAR_,
        "You cannot use operator<< with irregular nodes. Use operator<=.");
  }

  template <class... Args, bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator[](Args...) -> std::enable_if_t<!IS_TAIL_REGULAR_, void> {
    static_assert(IS_TAIL_REGULAR_,
                  "You cannot use operator[] with irregular nodes. Use "
                  "operator<= and ().");
  }

  template <class... Args, bool IS_TAIL_REGULAR_ = IS_TAIL_REGULAR>
  auto operator<=(Args...) -> std::enable_if_t<IS_TAIL_REGULAR_, void> {
    static_assert(!IS_TAIL_REGULAR_,
                  "You cannot use operator<= with regular nodes. Use "
                  "operator<< or operator[].");
  }

  template <class O, bool IS_NODE_REGULAR>
  HierarFlowChildren<HeadI, HeadO, O> operator||(
      HierarFlowNode<HeadI, O, IS_NODE_REGULAR> new_last) {
    return HierarFlowChildren<HeadI, HeadO, O>(head, new_last.impl);
  }

  template <class A, class B, class C, bool IS_PATH_REGULAR>
  HierarFlowChildren<HeadI, HeadO, A> operator||(
      HierarFlowPath<HeadI, A, B, C, IS_PATH_REGULAR> path) {
    return HierarFlowChildren<HeadI, HeadO, A>(head, path.head);
  }

  template <class ChildHeadO, class ChildTailO>
  HierarFlowChildren<HeadI, HeadO, ChildTailO> operator||(
      HierarFlowChildren<HeadI, ChildHeadO, ChildTailO> children) {
    // If the given children is an invalid instance, throw an error.
    if (children.IsInvalidInstance()) {
      throw exceptions::wrong_hierarflow_usage(
          "This HierarFlowChildren instance has been invalidated before.\n"
          "You should never use HierarFlowChildren instances twice by saving "
          "it as a variable.\n"
          "For example, `auto children = (a || b); c << (children || d); e << "
          "(children || e);` doesn't make sense.",
          __FILE__, __LINE__);
    }

    std::vector<std::shared_ptr<HierarFlowCallee<HeadI>>> new_children(1, head);

    new_children.insert(new_children.end(),
                        std::make_move_iterator(children.children.begin()),
                        std::make_move_iterator(children.children.end()));
    children.children.clear();

    return HierarFlowChildren<HeadI, HeadO, ChildTailO>(std::move(new_children),
                                                        *head);
  }

 private:
  HierarFlowPath(std::shared_ptr<HierarFlowNodeImpl<HeadI, HeadO>> head,
                 HierarFlowNodeImpl<TailI, TailO> &tail)
      : head(head), tail(tail) {}

  std::shared_ptr<HierarFlowNodeImpl<HeadI, HeadO>> head;
  HierarFlowNodeImpl<TailI, TailO> &tail;
};

}  // namespace fuzzuf::hierarflow

#endif
