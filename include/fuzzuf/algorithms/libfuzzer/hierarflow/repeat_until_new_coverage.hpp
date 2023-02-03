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
 * @file repeat_until_new_coverage.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_REPEAT_UNTIL_NEW_COVERAGE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_REPEAT_UNTIL_NEW_COVERAGE_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class RepeatUntilMutated
 * @brief Invoke all child nodes until execution result is marked as added to
 * corpus or retry count exceeded m. m is defined at the node creation. If
 * reduce_depth is enabled, the loop also breaks on no any unique features were
 * detected. This node modifies flow. The node takes 2 paths for state( to
 * retrive config.reduce_depth ) and execution result.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct RepeatUntilNewCoverage {};
template <typename R, typename... Args, typename Path>
class RepeatUntilNewCoverage<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param expected_ Expected mutation counts
   * @param max_ Max try counts
   */
  RepeatUntilNewCoverage(std::size_t cycle_) : cycle(cycle_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("RepeatUntilNewCoverage",
                                                     enter)
    for (std::size_t c = 0u; c != cycle; ++c) {
      if (this->CallSuccessors(std::forward<Args>(args)...)) {
        base_type::SetResponseValue(true);
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(
            "RepeatUntilNewCoverage", abort)
        return base_type::GoToParent();
      }
      bool break_ = false;
      Path()(
          [&](auto &&state, auto &&exec_result) {
            if (exec_result.added_to_corpus) break_ = true;

            if (state.create_info.config.reduce_depth &&
                !exec_result.found_unique_features)
              break_ = true;
          },
          std::forward<Args>(args)...);
      if (break_) {
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(
            "RepeatUntilNewCoverage", break_)
        break;
      }
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("RepeatUntilNewCoverage",
                                                     leave)
    return base_type::GoToDefaultNext();
  }

 private:
  std::size_t cycle;
};
namespace standard_order {
template <typename T>
using RepeatUntilNewCoverageStdArgOrderT = decltype(T::state && T::exec_result);
template <typename F, typename Ord>
using RepeatUntilNewCoverage =
    libfuzzer::RepeatUntilNewCoverage<F,
                                      RepeatUntilNewCoverageStdArgOrderT<Ord>>;
}  // namespace standard_order
}  // namespace fuzzuf::algorithm::libfuzzer
#endif
