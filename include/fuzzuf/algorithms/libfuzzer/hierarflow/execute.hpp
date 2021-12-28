/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_EXECUTE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_EXECUTE_HPP
#include "fuzzuf/algorithms/libfuzzer/executor/execute.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"
#include <memory>

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class Execute
 * @brief Run target with input specified by the Path, and acquire coverage,
 * outputs, execution result to the values specified by the Path. The node takes
 * 4 path for input, output, coverage and execution result.
 * @tparm F Function type to define what arguments passes through this node.
 * @tparm Path Struct path to define which value to to use.
 */
template <typename F, typename Executor, typename Path> struct Execute {};
template <typename R, typename... Args, typename Executor, typename Path>
struct Execute<R(Args...), Executor, Path>
    : public HierarFlowRoutine<R(Args...), R(Args...)> {
public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * @fn
   * Constructor
   * @param executor Executor to execute target program
   * @param use_afl_coverage If true, the node acquires coverage using
   * GetAFLFeedback. Otherwise, the node acquires coverage using GetBBFeedback.
   */
  Execute(std::unique_ptr<Executor> &&executor_, bool use_afl_coverage_)
      : executor(std::move(executor_)), use_afl_coverage(use_afl_coverage_) {
    assert(executor);
  }
  /**
   * @fn
   * This callable is called on HierarFlow execution
   * @param args arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("execute", enter)
    Path()(
        [&](auto &&...sorted) {
          executor::Execute(sorted..., *executor, use_afl_coverage);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(execute)
  }

private:
  std::unique_ptr<Executor> executor;
  bool use_afl_coverage;
};
namespace standard_order {
template <typename T>
using ExecuteStdArgOrderT =
    decltype(T::input && T::output && T::coverage && T::exec_result);
template <typename F, typename Executor, typename Ord>
using Execute = libfuzzer::Execute<F, Executor, ExecuteStdArgOrderT<Ord>>;
} // namespace standard_order

} // namespace fuzzuf::algorithm::libfuzzer
#endif
