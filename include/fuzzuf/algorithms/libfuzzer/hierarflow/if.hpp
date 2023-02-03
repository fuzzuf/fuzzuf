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
/**
 * @file if.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_IF_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_IF_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class If
 * @brief Invoke all child nodes if the callable returned true for the specified
 * conditions. The node takes 1 path for callable and 0 or more paths for
 * conditions.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct If {};
template <typename R, typename... Args, typename Path>
class If<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("If", enter)
    bool state = false;
    Path()([&](auto &&cond, auto &&...args_) { state = cond(args_...); },
           std::forward<Args>(args)...);
    if (!state) {
      FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("If", break_)
    } else if (this->CallSuccessors(std::forward<Args>(args)...)) {
      base_type::SetResponseValue(true);
      FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("If", abort)
      return base_type::GoToParent();
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("If", leave)
    return base_type::GoToDefaultNext();
  }
};

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
