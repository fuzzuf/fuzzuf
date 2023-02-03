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
 * @file marker.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_MARKER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_MARKER_HPP
#include <utility>

#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class Marker
 * @brief This node generates "mark" event with event detail defined at the node
 * creation. The event is received by NodeTracer, if one or more NodeTracers are
 * passed by arguments.
 *
 * This node is intended to make debugging easier.
 * The node takes no any paths.
 *
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam T Event detail type.
 */
template <typename F, typename T>
struct Marker {};
template <typename R, typename... Args, typename T>
struct Marker<R(Args...), T>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param info_ Event datail. This value is passed as is to NodeTracer.
   */
  Marker(T &&info_) : info(std::move(info_)) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Marker", enter)
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_MARK("Marker", info)
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(name)
  }

 private:
  T info;
};

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
