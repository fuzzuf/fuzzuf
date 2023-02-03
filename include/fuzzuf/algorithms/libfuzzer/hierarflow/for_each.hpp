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
 * @file for_each.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_FOR_EACH_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_FOR_EACH_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"
#include "fuzzuf/utils/range_traits.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class ForEachStaticData
 * @brief This node invokes all child nodes for each values in the container
 * defined at the node creation. On each loop head, a value from the container
 * is assigned to to value specified by the Path. This node modifies flow. The
 * node takes 1 path to write a value from container.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Data Container type. The value_type of type container must be
 * assignable to the value specified by the Path.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Data, typename Path>
class ForEachStaticData {};
template <typename R, typename... Args, typename Data, typename Path>
class ForEachStaticData<R(Args...), Data, Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * All arguments are transfered to constructor of the container
   */
  template <typename... T>
  ForEachStaticData(T &&...args) : data(std::forward<T>(args)...) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("ForEachStaticData", enter)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
    const std::size_t data_size = utils::range::rangeSize(data);
#pragma GCC diagnostic pop
    for (const auto &elem : data) {
      Path()([&](auto &&v) { utils::range::assign(elem, v); },
             std::forward<Args>(args)...);
      if (this->CallSuccessors(std::forward<Args>(args)...)) {
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("ForEachStaticData",
                                                         abort)
        base_type::SetResponseValue(true);
        return base_type::GoToParent();
      }
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("ForEachStaticData", leave)
    return base_type::GoToDefaultNext();
  }

 private:
  Data data;
};

/**
 * @class ForEachDynamicData
 * @brief This node invokes all child nodes for each values in the container
 * specified by the Path. On each loop head, a value from the container is
 * assigned to to value specified by the Path. This node modifies flow. The node
 * takes 2 paths. 1 for container and the other for writing a value from
 * container.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct ForEachDynamicData {};
template <typename R, typename... Args, typename Path>
struct ForEachDynamicData<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("ForEachDynamicData",
                                                     enter)
    bool aborted = false;
    Path()(
        [&](auto &&data, auto &&v) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
          const std::size_t data_size = utils::range::rangeSize(data);
#pragma GCC diagnostic pop
          for (const auto &elem : data) {
            utils::range::assign(elem, v);
            if (this->CallSuccessors(std::forward<Args>(args)...)) {
              base_type::SetResponseValue(true);
              aborted = true;
              return;
            }
          }
        },
        std::forward<Args>(args)...);
    if (aborted) {
      FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("ForEachDynamicData",
                                                       abort)
      return base_type::GoToParent();
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("ForEachDynamicData",
                                                     leave)
    return base_type::GoToDefaultNext();
  }
};
}  // namespace fuzzuf::algorithm::libfuzzer
#endif
