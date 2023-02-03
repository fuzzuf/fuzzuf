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
#ifndef FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_CALLEE_HPP
#define FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_CALLEE_HPP

#include <memory>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::hierarflow {

// Leave these as incomplete types.
template <class O>
class HierarFlowCaller;

template <class I, class O>
class HierarFlowRoutine;

using CalleeIndex = u32;

// HierarFlowCallee represents objects that are called by their predecessors
// with the arguments of type "IArgs..."

template <class I>
class HierarFlowCallee;

template <class IReturn, class... IArgs>
class HierarFlowCallee<IReturn(IArgs...)> {
  using I = IReturn(IArgs...);

  template <class A, class B>
  friend class HierarFlowRoutine;

 public:
  HierarFlowCallee() : parent(nullptr) {}

  HierarFlowCallee(HierarFlowCaller<I>* parent) : parent(parent) {}

  virtual ~HierarFlowCallee() {}

  virtual utils::NullableRef<HierarFlowCallee<I>> operator()(IArgs... args) = 0;

  const CalleeIndex& GetCalleeIndexRef() const { return idx; };

  HierarFlowCallee<I>& operator=(HierarFlowCallee<I>&& orig) {
    idx = orig.idx;
    std::swap(parent, orig.parent);
    return *this;
  }

  void SetParentAndIndex(HierarFlowCaller<I>* caller, CalleeIndex num) {
    if (parent) {
      throw exceptions::wrong_hierarflow_usage(
          "Node's parent can be set only once. "
          "You are trying to use the same node mutiple times "
          "in difference places.",
          __FILE__, __LINE__);
    }

    parent = caller;
    idx = num;
  }

  // Some utilities wants to directly set parent->resp_val.
  // We use SFINAE to define this function only when IReturn is not void.
  template <class IReturn_ = IReturn>
  auto SetParentResponseValue(const IReturn_& val)
      -> std::enable_if_t<!std::is_same_v<IReturn_, void>, void> {
    static_assert(!std::is_same_v<IReturn, void>,
                  "You cannot use this function when IReturn is void.");

    parent->resp_val = val;
  }

  template <class IReturn_ = IReturn>
  auto SetParentResponseValue(IReturn_&& val)
      -> std::enable_if_t<!std::is_same_v<IReturn_, void>, void> {
    static_assert(!std::is_same_v<IReturn, void>,
                  "You cannot use this function when IReturn is void.");

    parent->resp_val = std::move(val);
  }

 protected:
  CalleeIndex idx;
  // NOTE: we can't use std::reference_wrapper for incomplete types in C++17.
  // Hence, we use a raw pointer instead of NullableRef<HierarFlowCaller<I>>.
  HierarFlowCaller<I>* parent;
};

}  // namespace fuzzuf::hierarflow

#endif
