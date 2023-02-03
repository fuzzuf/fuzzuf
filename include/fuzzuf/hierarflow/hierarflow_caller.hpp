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
#ifndef FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_CALLER_HPP
#define FUZZUF_INCLUDE_HIERARFLOW_HIERARFLOW_CALLER_HPP

#include "fuzzuf/hierarflow/hierarflow_callee.hpp"
#include "fuzzuf/hierarflow/parent_traversable.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::hierarflow {

// HierarFlowCaller represents objects that call their successors
// with the arguments of type "OArgs..."

template <class O>
class HierarFlowCaller;

template <class OReturn, class... OArgs>
class HierarFlowCaller<OReturn(OArgs...)> : public ParentTraversable {
  using O = OReturn(OArgs...);

 public:
  HierarFlowCaller() : succ_nodes() {}

  HierarFlowCaller(HierarFlowCaller<O>&& orig)
      : resp_val(std::move(orig.resp_val)),
        succ_nodes(std::move(orig.succ_nodes)) {}

  virtual ~HierarFlowCaller() {}

  OReturn& GetResponseValue() { return resp_val; }

  virtual ParentTraversable* GetParent() = 0;

  std::vector<std::shared_ptr<HierarFlowCallee<O>>> succ_nodes;
  // the following is illegal if OReturn = void, so we specialize that case
  // below
  OReturn resp_val;
};

template <class... OArgs>
class HierarFlowCaller<void(OArgs...)>;

template <class... OArgs>
class HierarFlowCaller<void(OArgs...)> : public ParentTraversable {
  using O = void(OArgs...);

 public:
  HierarFlowCaller() : succ_nodes() {}

  HierarFlowCaller(HierarFlowCaller<O>&& orig)
      : succ_nodes(std::move(orig.succ_nodes)) {}

  virtual ~HierarFlowCaller() {}

  virtual ParentTraversable* GetParent() = 0;

  std::vector<std::shared_ptr<HierarFlowCallee<O>>> succ_nodes;
};

}  // namespace fuzzuf::hierarflow

#endif
