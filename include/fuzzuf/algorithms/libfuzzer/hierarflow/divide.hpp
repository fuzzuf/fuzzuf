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
 * @file divide.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_DIVIDE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_DIVIDE_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class Divide
 * @brief Invoke child nodes once for each n visits
 *
 * This node modifies flow.
 * The node takes no any paths.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path = utils::struct_path::Paths<>>
struct Divide {};
template <typename R, typename... Args, typename Path>
class Divide<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param d Child nodes are invoked for each d visits
   */
  Divide(std::size_t d) : numerator(0u), denominator(d) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Divide", enter)
    ++numerator;
    if (numerator == denominator) {
      if (this->CallSuccessors(std::forward<Args>(args)...)) {
        base_type::SetResponseValue(true);
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Divide", abort)
        return base_type::GoToParent();
      }
      numerator = 0u;
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Divide", leave)
    return base_type::GoToDefaultNext();
  }

 private:
  std::size_t numerator;
  std::size_t denominator;
};
}  // namespace fuzzuf::algorithm::libfuzzer
#endif
