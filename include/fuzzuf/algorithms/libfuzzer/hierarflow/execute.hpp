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
 * @file execute.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_EXECUTE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_EXECUTE_HPP
#include <memory>

#include "fuzzuf/algorithms/libfuzzer/executor/execute.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class Execute
 * @brief Run target with input specified by the Path, and acquire coverage,
 * outputs, execution result to the values specified by the Path. The node takes
 * 4 path for input, output, coverage and execution result.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(Execute,
                                                      executor::Execute)
namespace standard_order {
template <typename T>
using ExecuteStdArgOrderT =
    decltype(T::input && T::output && T::coverage && T::exec_result &&
             T::executors && T::executor_index && T::use_afl_coverage);
template <typename F, typename Ord>
using Execute = libfuzzer::Execute<F, ExecuteStdArgOrderT<Ord>>;

template <typename T>
using ExecuteSymCCStdArgOrderT =
    decltype(T::input && T::output && T::symcc_out && T::exec_result &&
             T::executors && T::symcc_target_offset);
template <typename F, typename Ord>
using ExecuteSymCC = libfuzzer::Execute<F, ExecuteSymCCStdArgOrderT<Ord>>;

}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
