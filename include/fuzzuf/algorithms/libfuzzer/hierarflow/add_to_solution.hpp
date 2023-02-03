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
 * @file add_to_solution.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_ADD_TO_SOLUTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_ADD_TO_SOLUTION_HPP
#include "fuzzuf/algorithms/libfuzzer/executor/add_to_solution.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class AddToSolution
 * @brief Insert execution result to solutions if the result is added to corpus
 * and target returned error status on exit. The node takes 2 paths for input
 * and exec_result.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct AddToSolution {};
template <typename R, typename... Args, typename Path>
struct AddToSolution<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param crashed_only_
   * If true, the result is added only if the target returned error status.
   * Otherwise, all passed execution results are added.
   * @param path_prefix_ Directory path to output solutions
   */
  AddToSolution(bool crashed_only_, const fs::path &path_prefix_)
      : crashed_only(crashed_only_), path_prefix(path_prefix_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("AddToSolution", enter)
    Path()(
        [&](auto &&...sorted) {
          executor::AddToSolution(sorted..., crashed_only, path_prefix);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(AddToSolution)
  }

 private:
  bool crashed_only;
  fs::path path_prefix;
};
namespace standard_order {
template <typename T>
using AddToSolutionStdArgOrderT = decltype(T::input && T::exec_result);
template <typename F, typename Ord>
using AddToSolution =
    libfuzzer::AddToSolution<F, AddToSolutionStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
