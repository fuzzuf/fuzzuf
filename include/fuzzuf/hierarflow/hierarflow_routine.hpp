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
#ifndef FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_ROUTINE_HPP
#define FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_ROUTINE_HPP

#include <type_traits>
#include <utility>

#include "fuzzuf/hierarflow/hierarflow_callee.hpp"
#include "fuzzuf/hierarflow/hierarflow_node_impl.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::hierarflow {

template <class I, class O>
class HierarFlowRoutine;

template <class IReturn, class... IArgs, class OReturn, class... OArgs>
class HierarFlowRoutine<IReturn(IArgs...), OReturn(OArgs...)> {
  using I = IReturn(IArgs...);
  using O = OReturn(OArgs...);
  friend HierarFlowNodeImpl<I, O>;

 public:
  using InputType = I;
  using OutputType = O;

  virtual ~HierarFlowRoutine() {}

 protected:
  // Only if IReturn is not void, we can get a response value.
  // Define the getter using SFINAE
  template <class IReturn_ = IReturn>
  auto GetResponseValue(void)
      -> std::enable_if_t<!std::is_void_v<IReturn_>,
                          typename std::add_lvalue_reference<IReturn>::type> {
    // Because IReturn_ is not identical to IReturn,
    // one can wrongly call this function even if IReturn == void
    static_assert(!std::is_void_v<IReturn>,
                  "You cannot use GetResponseValue when IReturn == void");

    return UnwrapCurrentLinkedNodeRef().parent->GetResponseValue();
  }

  // Only if IReturn is not void, we can set a response value.
  // Define the setter using SFINAE
  template <class IReturn_ = IReturn>
  auto SetResponseValue(IReturn_ val)
      -> std::enable_if_t<!std::is_void_v<IReturn_>, void> {
    // Because IReturn_ is not identical to IReturn,
    // one can wrongly call this function even if IReturn == void
    static_assert(!std::is_void_v<IReturn>,
                  "You cannot use SetResponseValue when IReturn == void");

    UnwrapCurrentLinkedNodeRef().parent->GetResponseValue() = val;
  }

  utils::NullableRef<HierarFlowCallee<I>> GoToParent(void) {
    return std::nullopt;
  }

  utils::NullableRef<HierarFlowCallee<I>> GoToDefaultNext(void) {
    auto &node = UnwrapCurrentLinkedNodeRef();
    if (node.parent == nullptr) return std::nullopt;
    if (node.idx + 1 == node.parent->succ_nodes.size()) return std::nullopt;
    return *node.parent->succ_nodes[node.idx + 1];
  }

  // FIXME: provide HierarFlowIrregularRoutine and remove virtual from this
  // function
  virtual OReturn CallSuccessors(OArgs... args) {
    // FIXME:
    // `HierarFlowCallee<I>::operator()` returns
    // `NullableRef<HierarFlowCallee<I>>` in the current implementation. This
    // was needed because HierarFlowNode was implemented with linked lists;
    // without pointer(or reference), we cannot point to the node that is to be
    // executed. However, now that the underlying data structure of
    // HierarFlowNode is replaced to vector, we can use the indices of the
    // vector instead of pointers to point to the next executed node. Therefore
    // this function should be updated to the following when backward
    // compatibility becomes unnecessary to remove the too long return type,
    // `NullableRef<HierarFlowCallee<I>>`:

    /*
    auto& succ_nodes = UnwrapCurrentLinkedNodeRef().succ_nodes;
    CalleeIndex succ_idx = 0;
    while (succ_idx < succ_nodes.size()) {
        succ_idx = succ_nodes[succ_idx](args...);
    }
    */

    runAllChildren(std::forward<OArgs>(args)...);

    if constexpr (std::is_same_v<OReturn, void>) {
      return;
    } else {
      return UnwrapCurrentLinkedNodeRef().resp_val;
    }
  }

  void runAllChildren(OArgs... args) {
    utils::NullableRef<HierarFlowCallee<O>> succ_ref = std::nullopt;
    auto &succ_nodes = UnwrapCurrentLinkedNodeRef().succ_nodes;
    if (!succ_nodes.empty()) {
      succ_ref = *succ_nodes[0];
    }

    while (succ_ref) {
      auto &succ = succ_ref.value().get();
      /*
       * FIXME: Although args should be std::forwarded to keep movable arguments
       * to be movable, in current implementation, it causes AFL to move an
       * unexpected values.
       */
      auto next_succ_ref = succ(args...);
      succ_ref.swap(next_succ_ref);
    }
  }

  virtual utils::NullableRef<HierarFlowCallee<I>> operator()(IArgs... args) = 0;

  utils::NullableRef<HierarFlowNodeImpl<I, O>> GetCurrentLinkedNodeRef(void) {
    return cur_linked_node_ref;
  }

  void SetCurrentLinkedNodeRef(
      utils::NullableRef<HierarFlowNodeImpl<I, O>> ref) {
    cur_linked_node_ref = ref;
  }

  HierarFlowNodeImpl<I, O> &UnwrapCurrentLinkedNodeRef() {
    return cur_linked_node_ref.value().get();
  }

 private:
  utils::NullableRef<HierarFlowNodeImpl<I, O>> cur_linked_node_ref;
};

}  // namespace fuzzuf::hierarflow

#endif
