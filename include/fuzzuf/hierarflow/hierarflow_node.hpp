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
#ifndef FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_NODE_HPP
#define FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_NODE_HPP

// FIXME: all the classes related to HierarFlow should be put under namespace
// fuzzuf::hierarflow

#include <memory>
#include <utility>

#include "fuzzuf/hierarflow/hierarflow_callee.hpp"
#include "fuzzuf/hierarflow/hierarflow_node_impl.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::hierarflow {

// Leave these as incomplete types.
template <class HeadI, class HeadO, class TailI, class TailO,
          bool IS_TAIL_REGULAR>
class HierarFlowPath;

template <class I, class HeadO, class TailO>
class HierarFlowChildren;

/**
 * @details The wrapper of HierarFlowNodeImpl. In order to support operators on
 * HierarFlowNodeImpl, HierarFlowNodeImpl should be always handled via
 * std::shared_ptr. This means we should not expose HierarFlowNodeImpl itself to
 * users because it may result in using HierarFlowNodeImpl without
 *          std::shared_ptr. Therefore this is the class actually the instance
 * of which users can create.
 * @tparam IS_REGULAR Fuzzuf has special nodes, such as CallRandomChild, that
 * act differently from usual nodes. For example, CallRandomChild randomly calls
 * only one child instead of calling their children one by one. Also, it's
 * possible that you and we will implement more other special nodes in the
 * future. Because it would be confusing if we treat such nodes in the same way
 * as usual nodes, we need to separate their type and the notation to use them.
 * @todo  We should duplicate HierarFlowRoutine and HierarFlowNodeImpl and
 * define HierarFlowIrregularRoutine and HierarFlowIrregularNodeImpl likewise.
 * Otherwise, we may treat irregular HierarFlowRoutines as regular ones by
 * mistake, and currently no error would be emitted for that mistake.
 */
template <class I, class O, bool IS_REGULAR = true>
class HierarFlowNode;

template <class IReturn, class... IArgs, class O, bool IS_REGULAR>
class HierarFlowNode<IReturn(IArgs...), O, IS_REGULAR> {
  using I = IReturn(IArgs...);

  template <class A, class B, bool C>
  friend class HierarFlowNode;

  template <class A, class B, class C, class D, bool E>
  friend class HierarFlowPath;

  template <class A, class B, class C>
  friend class HierarFlowChildren;

 public:
  HierarFlowNode() {}

  HierarFlowNode(std::shared_ptr<HierarFlowRoutine<I, O>> routine)
      : impl(new HierarFlowNodeImpl<I, O>(routine)) {}

  HierarFlowNode(const HierarFlowNode<I, O, IS_REGULAR>& src) {
    impl = src.impl;
  }

  HierarFlowNode(HierarFlowNode<I, O, IS_REGULAR>&& src) {
    impl = std::move(src.impl);
  }

  const CalleeIndex& GetCalleeIndexRef() const {
    return impl->GetCalleeIndexRef();
  };

  HierarFlowNode<I, O, IS_REGULAR>& operator=(
      const HierarFlowNode<I, O, IS_REGULAR>& src) {
    impl = src.impl;
    return *this;
  }

  HierarFlowNode<I, O, IS_REGULAR>& operator=(
      HierarFlowNode<I, O, IS_REGULAR>&& orig) {
    impl = std::move(orig.impl);
    return *this;
  }

  HierarFlowNodeImpl<I, O>& operator*() const { return *impl; }

  HierarFlowNodeImpl<I, O>* operator->() const { return impl.get(); }

  HierarFlowNode<I, O, IS_REGULAR> HardLink() {
    return HierarFlowNode<I, O, IS_REGULAR>(impl->ShareRoutine());
  }

  // operator<< should be defined only if IS_REGULAR is true(SFINAE).
  template <class O2, bool IS_SUCC_REGULAR, bool IS_REGULAR_ = IS_REGULAR>
  auto operator<<(HierarFlowNode<O, O2, IS_SUCC_REGULAR> succ)
      -> std::enable_if_t<IS_REGULAR_,
                          HierarFlowPath<I, O, O, O2, IS_SUCC_REGULAR>> {
    impl->AddSuccessor(succ.impl);
    return HierarFlowPath<I, O, O, O2, IS_SUCC_REGULAR>(impl, *succ.impl);
  }

  // operator[] should be defined only if IS_REGULAR is true(SFINAE).
  template <class O2, bool IS_SUCC_REGULAR, bool IS_REGULAR_ = IS_REGULAR>
  auto operator[](HierarFlowNode<O, O2, IS_SUCC_REGULAR> succ)
      -> std::enable_if_t<IS_REGULAR_,
                          HierarFlowPath<I, O, O, O2, IS_SUCC_REGULAR>> {
    return this->operator<<(succ);
  }

  // operator<= should be defined only if IS_REGULAR is false(SFINAE).
  template <class O2, bool IS_SUCC_REGULAR, bool IS_REGULAR_ = IS_REGULAR>
  auto operator<=(HierarFlowNode<O, O2, IS_SUCC_REGULAR> succ)
      -> std::enable_if_t<!IS_REGULAR_,
                          HierarFlowPath<I, O, O, O2, IS_SUCC_REGULAR>> {
    impl->AddSuccessor(succ.impl);
    return HierarFlowPath<I, O, O, O2, IS_SUCC_REGULAR>(impl, *succ.impl);
  }

  // The followings are defined the same way using SFINAE

  template <class T, class TailI, class TailO, bool IS_PATH_REGULAR,
            bool IS_REGULAR_ = IS_REGULAR>
  auto operator<<(HierarFlowPath<O, T, TailI, TailO, IS_PATH_REGULAR> path)
      -> std::enable_if_t<IS_REGULAR_,
                          HierarFlowPath<I, O, TailI, TailO, IS_PATH_REGULAR>> {
    impl->AddSuccessor(path.head);
    return HierarFlowPath<I, O, TailI, TailO, IS_PATH_REGULAR>(impl, path.tail);
  }

  template <class T, class TailI, class TailO, bool IS_PATH_REGULAR,
            bool IS_REGULAR_ = IS_REGULAR>
  auto operator[](HierarFlowPath<O, T, TailI, TailO, IS_PATH_REGULAR> path)
      -> std::enable_if_t<IS_REGULAR_,
                          HierarFlowPath<I, O, TailI, TailO, IS_PATH_REGULAR>> {
    return this->operator<<(path);
  }

  template <class T, class TailI, class TailO, bool IS_PATH_REGULAR,
            bool IS_REGULAR_ = IS_REGULAR>
  auto operator<=(HierarFlowPath<O, T, TailI, TailO, IS_PATH_REGULAR> path)
      -> std::enable_if_t<!IS_REGULAR_,
                          HierarFlowPath<I, O, TailI, TailO, IS_PATH_REGULAR>> {
    impl->AddSuccessor(path.head);
    return HierarFlowPath<I, O, TailI, TailO, IS_PATH_REGULAR>(impl, path.tail);
  }

  template <class ChildHeadO, class ChildTailO, bool IS_REGULAR_ = IS_REGULAR>
  auto operator<<(HierarFlowChildren<O, ChildHeadO, ChildTailO> children)
      -> std::enable_if_t<IS_REGULAR_,
                          HierarFlowPath<I, O, O, ChildHeadO, true>> {
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

    impl->AddSuccessors(std::move(children.children));
    children.children.clear();

    // FIXME: This permits `a << (b || c) << d`, which should never happen.
    // For the details, see the comments in HierarFlowPath.
    return HierarFlowPath<I, O, O, ChildHeadO, true>(impl,
                                                     children.first_child);
  }

  template <class ChildHeadO, class ChildTailO, bool IS_REGULAR_ = IS_REGULAR>
  auto operator[](HierarFlowChildren<O, ChildHeadO, ChildTailO> children)
      -> std::enable_if_t<IS_REGULAR_,
                          HierarFlowPath<I, O, O, ChildHeadO, true>> {
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

  template <class ChildHeadO, class ChildTailO, bool IS_REGULAR_ = IS_REGULAR>
  auto operator<=(HierarFlowChildren<O, ChildHeadO, ChildTailO> children)
      -> std::enable_if_t<!IS_REGULAR_,
                          HierarFlowPath<I, O, O, ChildHeadO, true>> {
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

    impl->AddSuccessors(std::move(children.children));
    children.children.clear();

    return HierarFlowPath<I, O, O, ChildHeadO, true>(impl,
                                                     children.first_child);
  }

  // To emit human-readable compilation errors, we intentionally make
  // static_assert fail in prohibited(i.e. undefined in SFINAE) cases

  template <class... Args, bool IS_REGULAR_ = IS_REGULAR>
  auto operator<<(Args...) -> std::enable_if_t<!IS_REGULAR_, void> {
    static_assert(
        IS_REGULAR_,
        "You cannot use operator<< with irregular nodes. Use operator<=.");
  }

  template <class... Args, bool IS_REGULAR_ = IS_REGULAR>
  auto operator[](Args...) -> std::enable_if_t<!IS_REGULAR_, void> {
    static_assert(IS_REGULAR_,
                  "You cannot use operator[] with irregular nodes. Use "
                  "operator<= and ().");
  }

  template <class... Args, bool IS_REGULAR_ = IS_REGULAR>
  auto operator<=(Args...) -> std::enable_if_t<IS_REGULAR_, void> {
    static_assert(!IS_REGULAR_,
                  "You cannot use operator<= with regular nodes. Use "
                  "operator<< or operator[].");
  }

  template <class O2, bool IS_NODE_REGULAR>
  HierarFlowChildren<I, O, O2> operator||(
      HierarFlowNode<I, O2, IS_NODE_REGULAR> brother) {
    return HierarFlowChildren<I, O, O2>(impl, brother.impl);
  }

  template <class O2, class O3>
  HierarFlowChildren<I, O, O3> operator||(
      HierarFlowChildren<I, O2, O3> children) {
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

    std::vector<std::shared_ptr<HierarFlowCallee<I>>> new_children(1, impl);

    new_children.insert(new_children.end(),
                        std::make_move_iterator(children.children.begin()),
                        std::make_move_iterator(children.children.end()));
    children.children.clear();

    return HierarFlowChildren<I, O, O3>(std::move(new_children), *impl);
  }

  template <class HeadO, class TailI, class TailO, bool IS_PATH_REGULAR>
  HierarFlowChildren<I, O, HeadO> operator||(
      HierarFlowPath<I, HeadO, TailI, TailO, IS_PATH_REGULAR> path) {
    return HierarFlowChildren<I, O, HeadO>(impl, path.head);
  }

  // We define operator() only if IReturn == void, in order to avoid
  // crashes(SFINAE). For details, see the comment of WrapToMakeHeadNode.
  template <class IReturn_ = IReturn>
  auto operator()(IArgs... args)
      -> std::enable_if_t<std::is_void_v<IReturn_>, void> {
    (*impl)(std::forward<IArgs>(args)...);
  }

  // If IReturn == void, then simply emit a compilation error with
  // static_assert.
  template <class IReturn_ = IReturn>
  auto operator()(IArgs...)
      -> std::enable_if_t<!std::is_void_v<IReturn_>, void> {
    static_assert(std::is_void_v<IReturn_>,
                  "You cannot use operator() when IReturn != void. Use "
                  "WrapToMakeHeadNode.");
  }

  // Using this function a lot is not recommended. But some of utilities require
  // this...
  std::shared_ptr<HierarFlowNodeImpl<I, O>> ShareImpl() { return impl; }

 private:
  std::shared_ptr<HierarFlowNodeImpl<I, O>> impl;
};

}  // namespace fuzzuf::hierarflow

#endif
