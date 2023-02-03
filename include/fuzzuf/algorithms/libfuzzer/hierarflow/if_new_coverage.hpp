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
 * @file if_new_coverage.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_IF_NEW_COVERAGE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_IF_NEW_COVERAGE_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/if.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {
namespace standard_order {
template <typename T>
using IfNewCoverageStdArgOrderT =
    decltype(fuzzuf::utils::struct_path::root /
                 fuzzuf::utils::struct_path::ident<std::equal_to<bool>> &&
             T::added_to_corpus &&
             fuzzuf::utils::struct_path::root /
                 fuzzuf::utils::struct_path::int_<bool, true>);
template <typename F, typename Ord>
using IfNewCoverage = libfuzzer::If<F, IfNewCoverageStdArgOrderT<Ord>>;
}  // namespace standard_order
}  // namespace fuzzuf::algorithm::libfuzzer
#endif
