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
#ifndef FUZZUF_INCLUDE_HIERARFLOW_UTILITY_HPP
#define FUZZUF_INCLUDE_HIERARFLOW_UTILITY_HPP

#include <memory>
#include <random>
#include <type_traits>
#include <utility>

#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::hierarflow {

/**
 * @brief Create a new HierarFlowNode instance with the given class that derives
 * HierarFlowRoutine
 * @tparam RoutineDerived the class of the routine that will be connected with
 * the returned node. It should derive HierarFlowRoutine.
 * @param args the arguments passed to the RoutineDerived constructor
 */
template <class RoutineDerived, class... Args>
HierarFlowNode<typename RoutineDerived::InputType,
               typename RoutineDerived::OutputType>
CreateNode(Args&&... args) {
  using I = typename RoutineDerived::InputType;
  using O = typename RoutineDerived::OutputType;

  return HierarFlowNode<I, O>(std::shared_ptr<HierarFlowRoutine<I, O>>(
      new RoutineDerived(std::forward<Args>(args)...)));
}

/**
 * @brief Create a new HierarFlowIrregularNode instance with the given class
 that derives HierarFlowRoutine.
 * @tparam RoutineDerived the class of the routine cthat will be connected with
 the returned node. It should derive HierarFlowRoutine.
 * @param args the arguments passed to the RoutineDerived constructor.
 * @note In the future, HierarFlowRoutine and HierarFlowIrregularRoutine should
 be separated,
 *       and this function should receive only HierarFlowIrregularRoutine.
 *       However, they are treated the same way currently.
 */
template <class RoutineDerived, class... Args>
HierarFlowNode<typename RoutineDerived::InputType,
               typename RoutineDerived::OutputType, false>
CreateIrregularNode(Args&&... args) {
  using I = typename RoutineDerived::InputType;
  using O = typename RoutineDerived::OutputType;

  return HierarFlowNode<I, O, false>(std::shared_ptr<HierarFlowRoutine<I, O>>(
      new RoutineDerived(std::forward<Args>(args)...)));
}

/**
 * @brief ProxyRoutine is a routine that works as a kind of proxy, passing the
 * received arguments to the children.
 * @details This routine (and the node created from this) is convenient to just
 * chain mutilple nodes that have the same IReturn(IArgs...).
 */
template <class I>
class ProxyRoutine;

template <class IReturn, class... IArgs>
class ProxyRoutine<IReturn(IArgs...)>
    : public HierarFlowRoutine<void(IArgs...), IReturn(IArgs...)> {
 public:
  ProxyRoutine(void) {}

  utils::NullableRef<HierarFlowCallee<void(IArgs...)>> operator()(
      IArgs... args) {
    this->CallSuccessors(std::forward<IArgs>(args)...);
    return this->GoToParent();
  }
};

/**
 * @brief Create a new HierarFlowNode instance that has ProxyRoutine as its
 * routine, while setting a given node as its child.
 * @details Sometimes, users may want to use, as the root routine, routines
 * whose IReturn is not void. However, calling SetReponseValue in the root
 * routine causes a crash because it expects the reference of parent's
 * resp_val(which is actually null). Hence, we don't define operator() for those
 * routines and such usage is prohibited. Therefore, we provide the way of
 *          creating a dummy root which just calls the successors with provided
 * arguments.
 */
template <class IReturn, class... IArgs, class O, bool IS_REGULAR>
HierarFlowNode<void(IArgs...), IReturn(IArgs...), true> WrapToMakeHeadNode(
    HierarFlowNode<IReturn(IArgs...), O, IS_REGULAR> node) {
  auto head = CreateNode<ProxyRoutine<IReturn(IArgs...)>>();
  head << node;
  return head;
}

/**
 * @brief Create a new HierarFlowNode instance that has ProxyRoutine<I> as its
 * routine, for the specified I.
 * @details It would be convenient if we provide a dummy parent node to chain
 * multiple nodes whose I is all the same.
 */
template <class I>
auto CreateDummyParent(void) {
  return CreateNode<ProxyRoutine<I>>();
}

/**
 * @brief CallRandomChild is a irregular routine that randomly chooses and calls
 * only one of its children when executed.
 * @details It's sometimes convenient to have the routine that randomly picks
 * one node from its children and executes that node. This can be used for
 * random mutations or some other procedures that should have random behavior.
 * @todo This should derive from HierarFlowIrregularRoutine instead of
 * HierarFlowRoutine after HierarFlowIrregularRoutine is implemented.
 * @todo Fuzzuf should unify its class designs of random number generators and
 * distributions so that all the classes would not uncontrollably define its
 * random number generator and distributions in their own way. After the
 *       unification, CallRandomChild should follow the sole design to define
 * its distribution. Currently, we use std::default_random_engine with ordinary
 * modulus.
 * @todo This routine can be more useful if it can deal with other distributions
 * than the uniform distribution.
 */
template <class I>
class CallRandomChild;

template <class IReturn, class... IArgs>
class CallRandomChild<IReturn(IArgs...)>
    : public HierarFlowRoutine<IReturn(IArgs...), IReturn(IArgs...)> {
 public:
  CallRandomChild(void) : engine() {}

  utils::NullableRef<HierarFlowCallee<IReturn(IArgs...)>> operator()(
      IArgs... args) {
    auto& node = this->UnwrapCurrentLinkedNodeRef();
    auto& succ_nodes = node.succ_nodes;

    auto sz = succ_nodes.size();
    if (sz == 0) return this->GoToDefaultNext();

    (*succ_nodes[engine() % sz])(args...);

    if constexpr (!std::is_same_v<IReturn, void>) {
      // To avoid unnecessary copy, use std::move.
      node.SetParentResponseValue(std::move(node.resp_val));
    }

    return this->GoToDefaultNext();
  }

 private:
  std::default_random_engine engine;
};

/**
 * @brief FinalizeRoutine is a routine that calls a specified node directly
 * after calling the successor nodes.
 * @details Sometimes, there should be a control flow that has a kind of "try"
 * block and "finally" block. This routine is convenient to express "finally"
 * blocks. The routine has a HierarFlowNode instance as a member variable, and
 * call it after calling the ordinary successors of the routine.
 */
template <class I, class O>
class FinalizeRoutine;

template <class IReturn, class... IArgs, class OReturn, class... OArgs>
class FinalizeRoutine<IReturn(IArgs...), OReturn(OArgs...)>
    : public HierarFlowRoutine<IReturn(IArgs...), IReturn(IArgs...)> {
  using I = IReturn(IArgs...);
  using O = OReturn(OArgs...);

  template <class A, class B>
  friend HierarFlowNode<A, A> Finally(HierarFlowNode<A, B> node);

 public:
  utils::NullableRef<HierarFlowCallee<IReturn(IArgs...)>> operator()(
      IArgs... args) {
    // FIXME: this should be updated as with `HierarFlowRoutine::CallSuccessors`
    // when backward compatibility becomes unnecessary. For the details, see the
    // comment in `HierarFlowRoutine::CallSuccessors`.

    utils::NullableRef<HierarFlowCallee<I>> succ_ref = std::nullopt;
    auto& node = this->UnwrapCurrentLinkedNodeRef();
    auto& succ_nodes = node.succ_nodes;

    if (!succ_nodes.empty()) {
      succ_ref = *succ_nodes[0];
    }

    // This is exactly the same as HierarFlowRoutine::CallSuccessors
    while (succ_ref) {
      auto& succ = succ_ref.value().get();
      auto next_succ_ref = succ(args...);
      succ_ref.swap(next_succ_ref);
    }

    // Call the special node after all the ordinary successors have ended.
    HierarFlowCallee<I>& final_ref = *final_node_impl;
    final_ref(args...);

    if constexpr (!std::is_same_v<IReturn, void>) {
      // To avoid unnecessary copy, use std::move.
      node.SetParentResponseValue(std::move(node.resp_val));
    }

    return this->GoToDefaultNext();
  }

 private:
  // Exposing this class to public is very dangerous because this routine has a
  // HierarFlowNode instance.
  FinalizeRoutine(std::shared_ptr<HierarFlowNodeImpl<I, O>> impl)
      : final_node_impl(impl) {}

  // For the same reason, prohibit copy constructors(,
  // HierarFlowNodeImpl::ShareRoutine and HierarFlowNode::HardLink).
  FinalizeRoutine(const FinalizeRoutine&) = delete;
  FinalizeRoutine& operator=(const FinalizeRoutine&) = delete;

  std::shared_ptr<HierarFlowNodeImpl<I, O>> final_node_impl;
};

/**
 * @brief Create a finally block in HierarFlow.
 * @details Sometimes, there should be a control flow that has a kind of "try"
 * block and "finally" block. This function creates a node that describes such
 * control flows. Successors connected to this node express the procedures in a
 * "try" block; when this node is called, this node's operator() directly calls
 * those successors. The argument of Finally expresses the procedure in a
 * "finally" block; regardless of the values that the successors returned, that
 * argument is called subsequently.
 */
template <class I, class O>
HierarFlowNode<I, I> Finally(HierarFlowNode<I, O> node) {
  auto impl = node.ShareImpl();
  auto ret = HierarFlowNode<I, I>(std::shared_ptr<HierarFlowRoutine<I, I>>(
      new FinalizeRoutine<I, O>(impl)));

  // We don't connect ret and node by `ret << node`.
  // This is because we don't want node to appear in the successors of ret.
  // So we just tell node that ret is the parent of it instead.
  impl->SetParentAndIndex(ret.ShareImpl().get(), 0);

  return ret;
}

}  // namespace fuzzuf::hierarflow

#endif
