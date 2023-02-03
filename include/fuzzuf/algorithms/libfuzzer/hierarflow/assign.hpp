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
 * @file assign.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_ASSIGN_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_ASSIGN_HPP
#include <tuple>

#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class StaticAssign
 * @brief Assign value defined at the node creation to the value specified by
 * the Path. The node takes 1 path for output value.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
class StaticAssign {};
template <typename R, typename... Args, typename Path>
class StaticAssign<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * All arguments are transfered to constructor of the assign value
   */
  template <typename... TArgs>
  StaticAssign(TArgs &&...args) : initial(std::forward<TArgs>(args)...) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticAssign", enter)
    Path()([&](auto &&v) { utils::range::assign(initial, v); },
           std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(StaticAssign)
  }

 private:
  utils::type_traits::RemoveCvrT<
      utils::struct_path::PointedTypeT<R(Args...), Path>>
      initial;
};

/**
 * @class DynamicAssign
 * @brief Assign value specified by the Path to the value specified by the Path.
 * The node takes 2 paths for input value and output value.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(DynamicAssign,
                                                      utils::range::assign)

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
