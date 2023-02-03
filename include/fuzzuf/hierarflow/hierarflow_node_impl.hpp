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
#ifndef FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_NODE_IMPL_HPP
#define FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_NODE_IMPL_HPP

#include <memory>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/hierarflow/hierarflow_callee.hpp"
#include "fuzzuf/hierarflow/hierarflow_caller.hpp"
#include "fuzzuf/hierarflow/parent_traversable.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::hierarflow {

// Leave these as incomplete types.
template <class I, class O>
class HierarFlowRoutine;

template <class I, class O, bool IS_REGULAR>
class HierarFlowNode;

template <class HeadI, class HeadO, class TailI, class TailO,
          bool IS_TAIL_REGULAR>
class HierarFlowPath;

template <class I, class HeadO, class TailO>
class HierarFlowChildren;

/**
 * @note Why do we need HierarFlowNodeImpl?: see the comment of HierarFlowNode.
 */
template <class I, class O>
class HierarFlowNodeImpl;

template <class IReturn, class... IArgs, class OReturn, class... OArgs>
class HierarFlowNodeImpl<IReturn(IArgs...), OReturn(OArgs...)>
    : public HierarFlowCallee<IReturn(IArgs...)>,
      public HierarFlowCaller<OReturn(OArgs...)> {
  using I = IReturn(IArgs...);
  using O = OReturn(OArgs...);

  template <class A, class B, bool C>
  friend class HierarFlowNode;

  template <class A, class B, class C, class D, bool E>
  friend class HierarFlowPath;

  template <class A, class B, class C>
  friend class HierarFlowChildren;

 private:
  HierarFlowNodeImpl() {}

  HierarFlowNodeImpl(HierarFlowNodeImpl<I, O>&& orig)
      : HierarFlowCallee<I>(orig),
        HierarFlowCaller<O>(orig),
        routine(std::move(orig.routine)) {}

  HierarFlowNodeImpl<I, O>& operator=(HierarFlowNodeImpl<I, O>&& orig) {
    HierarFlowCallee<I>::operator=(std::move(orig));
    HierarFlowCaller<O>::operator=(std::move(orig));

    routine.swap(orig.routine);
    this->succ_nodes.swap(orig.succ_nodes);
    return *this;
  }

  HierarFlowNodeImpl(std::shared_ptr<HierarFlowRoutine<I, O>> routine)
      : HierarFlowCallee<I>(), HierarFlowCaller<O>(), routine(routine) {}

  HierarFlowNodeImpl(HierarFlowCaller<I>& parent,
                     std::shared_ptr<HierarFlowRoutine<I, O>> routine)
      : HierarFlowCallee<I>(&parent), HierarFlowCaller<O>(), routine(routine) {}

  utils::NullableRef<HierarFlowCallee<I>> operator()(IArgs... args) {
    if constexpr (!std::is_same_v<OReturn, void>) {
      // Initialize OReturn. This means, OReturn must be a type which is movable
      // and which has the default constructor
      this->resp_val = OReturn();
    }

    auto pre_linked = routine->GetCurrentLinkedNodeRef();
    routine->SetCurrentLinkedNodeRef(*this);

    auto ret = (*routine)(std::forward<IArgs>(args)...);

    routine->SetCurrentLinkedNodeRef(pre_linked);
    return ret;
  }

  std::shared_ptr<HierarFlowRoutine<I, O>> ShareRoutine(void) {
    return routine;
  }

  /**
   * @brief Check if this node is contained in a cycle. If so, throw an
   * error(which should be non-recoverable).
   * @details HierarFlow should be a tree. It's not allowed to have cycles in
   * its graph. We need to make sure of it before flows get executed. In the
   * current implementation, this check is done everytime some node is set as
   * the parent of some node(e.g., operator<<, operator<=, operator[] are used).
   *          This function is used for this check. By recursively traversing
   * parents starting from this node, we can make sure that, at least, there is
   * no cycle containing this node. Since this function is called everytime
   * nodes are connected, finally it's also guaranteed that there is no cycle at
   * all in the entire graph.
   */
  void GuaranteeNoLoop(void) {
    std::set<ParentTraversable*> appeared_ptrs;

    auto parent_ptr = GetParent();
    while (parent_ptr) {
      if (appeared_ptrs.count(parent_ptr) > 0) {
        throw exceptions::wrong_hierarflow_usage(
            "A cycle is detected in this HierarFlow definition. "
            "Currently, HierarFlow cannot contain loops in a graph.",
            __FILE__, __LINE__);
      }
      appeared_ptrs.insert(parent_ptr);
      parent_ptr = parent_ptr->GetParent();
    }
  }

  /**
   * @note Due to GuaranteeNoLoop(), constructing a tree takes O(N^2).
   */
  template <class O2>
  void AddSuccessor(std::shared_ptr<HierarFlowNodeImpl<O, O2>> node) {
    CalleeIndex node_idx = this->succ_nodes.size();
    node->SetParentAndIndex(this, node_idx);
    this->succ_nodes.emplace_back(node);

    GuaranteeNoLoop();
  }

  /**
   * @note Due to GuaranteeNoLoop(), constructing a tree takes O(N^2).
   */
  void AddSuccessors(
      std::vector<std::shared_ptr<HierarFlowCallee<O>>>&& nodes) {
    CalleeIndex node_idx = this->succ_nodes.size();
    for (auto node : nodes) {
      node->SetParentAndIndex(this, node_idx++);
    }

    this->succ_nodes.insert(this->succ_nodes.end(),
                            std::make_move_iterator(nodes.begin()),
                            std::make_move_iterator(nodes.end()));

    GuaranteeNoLoop();
  }

  virtual ParentTraversable* GetParent() { return this->parent; }

  std::shared_ptr<HierarFlowRoutine<I, O>> routine;
};

}  // namespace fuzzuf::hierarflow

#endif
