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
 * @file standard_typedef.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEF_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEF_HPP

#include <tuple>
#include <type_traits>

#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

/**
 * Macro to generate standard typedefs for libFuzzer nodes.
 */
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS     \
  using input_cb_t = R(Args...);                                    \
  using output_cb_t = input_cb_t;                                   \
  using callee_ref_t =                                              \
      utils::NullableRef<hierarflow::HierarFlowCallee<input_cb_t>>; \
  using base_type = hierarflow::HierarFlowRoutine<input_cb_t, output_cb_t>;

#endif
