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
 * @file print_status_for_new_unit.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_PRINT_STATUS_FOR_NEW_UNIT_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_PRINT_STATUS_FOR_NEW_UNIT_HPP
#include <cstdint>

#include "fuzzuf/algorithms/libfuzzer/executor/print_status_for_new_unit.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class PrintStatusForNewUnit
 * @brief Print execution result and fuzzer state as in the format similar to
 * original implementation. The node takes 7 paths for input, execution result,
 * max length, mutation history, dictionary history, fuzzer loop count and date
 * of started fuzzing.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct PrintStatusForNewUnit {};
template <typename R, typename... Args, typename Path>
struct PrintStatusForNewUnit<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param verbosity_
   * If 0, display coverage novelty only. If 1, display mutation history and
   * dictionary history for limited length in addition to novelity. If 2,
   * display full mutation history and dictionary history in addition to
   * novelity.
   * @param max_mutations_to_print
   * Max element count of mutation history and dictionary history displayed in
   * the case that verbosity is 1.
   * @param max_unit_size_to_print
   * If the input length in bytes is shorter than this value, display the input.
   * @param sink
   * Callback function with string as an argument that is called to display
   * message.
   */
  template <typename Sink>
  PrintStatusForNewUnit(unsigned int verbosity_,
                        std::size_t max_mutations_to_print_,
                        std::size_t max_unit_size_to_print_, Sink &&sink_)
      : verbosity(verbosity_),
        max_mutations_to_print(max_mutations_to_print_),
        max_unit_size_to_print(max_unit_size_to_print_),
        sink(std::forward<Sink>(sink_)) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("PrintStatusForNewUnit",
                                                     enter)
    Path()(
        [&](auto &&...sorted) {
          executor::PrintStatusForNewUnit(sorted..., verbosity,
                                          max_mutations_to_print,
                                          max_unit_size_to_print, sink);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(PrintStatusForNewUnit)
  }

 private:
  unsigned int verbosity;
  std::size_t max_mutations_to_print;
  std::size_t max_unit_size_to_print;
  std::function<void(std::string &&)> sink;
};
namespace standard_order {
template <typename T>
using PrintStatusForNewUnitStdArgOrderT =
    decltype(T::input && T::exec_result && T::max_length &&
             T::mutation_history && T::dict_history && T::count &&
             T::begin_date);
template <typename F, typename Ord>
using PrintStatusForNewUnit =
    libfuzzer::PrintStatusForNewUnit<F, PrintStatusForNewUnitStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
