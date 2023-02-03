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
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_HIERARFLOW_ADD_TO_SOLUTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_HIERARFLOW_ADD_TO_SOLUTION_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/nezha/executor/add_to_solution.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::nezha {

/**
 * @class AddToSolution
 * @brief Insert execution result to solutions if the tuple of multipe execution
 * results is unique. The node takes 6 paths for input, execution result,
 * current trace, known traces, current outputs and known outputs. Current trace
 * is a container of bool which represents whether the execution result was
 * added to corpus. Current outputs is a container of integer which represent
 * the hash value of standard output from each target.
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
   * @param path_prefix_ Directory path to output solutions
   */
  AddToSolution(const fs::path &path_prefix_) : path_prefix(path_prefix_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("AddToSolution", enter)
    Path()(
        [&](auto &&...sorted) {
          executor::AddToSolution(sorted..., path_prefix);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(AddToSolution)
  }

 private:
  fs::path path_prefix;
};
namespace standard_order {
template <typename T>
using AddToSolutionStdArgOrderT =
    decltype(T::input && T::exec_result && T::trace && T::known_traces &&
             T::outputs && T::known_outputs);
template <typename F, typename Ord>
using AddToSolution = nezha::AddToSolution<F, AddToSolutionStdArgOrderT<Ord>>;
}  // namespace standard_order
}  // namespace fuzzuf::algorithm::nezha

#endif
