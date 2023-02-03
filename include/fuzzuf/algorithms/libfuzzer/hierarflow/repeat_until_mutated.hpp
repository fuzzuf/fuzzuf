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
 * @file repeat_until_mutated.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_REPEAT_UNTIL_MUTATED_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_REPEAT_UNTIL_MUTATED_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class RepeatUntilMutated
 * @brief Invoke all child nodes until input is mutated n times or retry count
 * exceeded m. n and m are defined at the node creation. Mutated count is
 * retrived from mutation history. Since mutator fails to mutate in some
 * cases(ex. the input length is max and trying to insert something) and
 * mutation history is recorded only if mutation succeeded, total loop count can
 * be larger than expected mutation count. This node modifies flow. The node
 * takes 1 path for mutation history
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct RepeatUntilMutated {};
template <typename R, typename... Args, typename Path>
class RepeatUntilMutated<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param expected_ Expected mutation counts
   * @param max_ Max try counts
   */
  RepeatUntilMutated(std::size_t expected_, std::size_t max_)
      : expected(expected_), max(max_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("RepeatUntilMutated",
                                                     enter)
    std::size_t initial_size = 0u;
    Path()(
        [&](auto &&mutation_history) {
          initial_size = mutation_history.size();
        },
        std::forward<Args>(args)...);
    for (std::size_t c = 0u; c != max; ++c) {
      if (this->CallSuccessors(std::forward<Args>(args)...)) {
        base_type::SetResponseValue(true);
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("RepeatUntilMutated",
                                                         abort)
        return base_type::GoToParent();
      }
      bool break_ = false;
      Path()(
          [&](auto &&mutation_history) {
            if (mutation_history.size() >= initial_size + expected)
              break_ = true;
          },
          std::forward<Args>(args)...);
      if (break_) {
        FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("RepeatUntilMutated",
                                                         break_)
        break;
      }
    }
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("RepeatUntilMutated",
                                                     leave)
    return base_type::GoToDefaultNext();
  }

 private:
  std::size_t expected;
  std::size_t max;
};
namespace standard_order {
template <typename T>
using RepeatUntilMutatedStdArgOrderT = decltype(T::mutation_history);
template <typename F, typename Ord>
using RepeatUntilMutated =
    libfuzzer::RepeatUntilMutated<F, RepeatUntilMutatedStdArgOrderT<Ord>>;
}  // namespace standard_order
}  // namespace fuzzuf::algorithm::libfuzzer
#endif
