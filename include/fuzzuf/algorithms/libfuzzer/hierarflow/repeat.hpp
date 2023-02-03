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
 * @file repeat.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_REPEAT_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_REPEAT_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class StaticRepeat
 * @brief Invoke all child nodes n times. n is defined at the node creation.
 * This node modifies flow.
 * The node takes no any Paths.
 * @tparam F Function type to define what arguments passes through this node.
 */
template <typename F>
struct StaticRepeat {};
template <typename R, typename... Args>
class StaticRepeat<R(Args...)>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param cycle_ Number of loop cycles
   */
  StaticRepeat(std::size_t cycle_) : cycle(cycle_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticRepeat", enter)
    for (size_t c = 0u; c != cycle; ++c) {
      if (this->CallSuccessors(std::forward<Args>(args)...)) {
        base_type::SetResponseValue(true);
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticRepeat", abort)
        return base_type::GoToParent();
      }
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticRepeat", leave)
    return base_type::GoToDefaultNext();
  }

 private:
  std::size_t cycle;
};

/**
 * @class PartiallyDynamicRepeat
 * @brief Invoke all child nodes until loop counter is equal or greater than
 * total cycles. Total cycles is defined at the node creation. The node takes 1
 * path for loop counter. Note that loop counter must be incremented maually, or
 * this node will never complete.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct PartiallyDynamicRepeat {};
template <typename R, typename... Args, typename Path>
class PartiallyDynamicRepeat<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param cycle_ Number of loop cycles
   */
  PartiallyDynamicRepeat(std::size_t cycle_) : cycle(cycle_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("PartiallyDynamicRepeat",
                                                     enter)
    while (1) {
      bool break_ = false;
      std::size_t count_ = 0u;
      Path()(
          [&](auto &&count) {
            count_ = count;
            break_ = count >= cycle;
          },
          std::forward<Args>(args)...);
      if (break_) {
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(
            "PartiallyDynamicRepeat", break_)
        break;
      }
      if (this->CallSuccessors(std::forward<Args>(args)...)) {
        base_type::SetResponseValue(true);
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(
            "PartiallyDynamicRepeat", abort)
        return base_type::GoToParent();
      }
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("PartiallyDynamicRepeat",
                                                     leave)
    return base_type::GoToDefaultNext();
  }

 private:
  std::size_t cycle;
};

/**
 * @class DynamicRepeat
 * @brief Invoke all child nodes until loop counter is equal or greater than
 * total cycles. Total cycles is specified by the Path. The node takes 2 paths
 * for loop counter and total cycles. Note that loop counter must be incremented
 * maually, or this node will never complete.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct DynamicRepeat {};
template <typename R, typename... Args, typename Path>
class DynamicRepeat<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Repeat", enter)
    while (1) {
      bool state = false;
      Path()([&](auto &&cond, auto &&...args_) { state = cond(args_...); },
             std::forward<Args>(args)...);
      if (!state) {
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Repeat", break_)
        break;
      }
      if (this->CallSuccessors(std::forward<Args>(args)...)) {
        base_type::SetResponseValue(true);
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Repeat", abort)
        return base_type::GoToParent();
      }
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Repeat", leave)
    return base_type::GoToDefaultNext();
  }
};

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
