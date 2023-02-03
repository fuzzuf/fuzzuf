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
 * @file gather.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_HIERARFLOW_GATHER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_HIERARFLOW_GATHER_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/nezha/executor/gather_output.hpp"

namespace fuzzuf::algorithm::nezha {

/**
 * @class GatherOutput
 * @brief Append hash value of value specified by the Path to the value
 * specified by the Path. This node takes two Paths for value to be hashed and
 * container to append hash value.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(GatherOutput,
                                                      executor::GatherOutput)
namespace standard_order {
template <typename T>
using GatherOutputStdArgOrderT = decltype(T::output && T::outputs);
template <typename F, typename Ord>
using GatherOutput = nezha::GatherOutput<F, GatherOutputStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::nezha

#endif
