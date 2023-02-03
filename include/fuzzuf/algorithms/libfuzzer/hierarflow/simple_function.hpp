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
 * @file simple_function.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

/**
 * In the case that HierarFlow node doesn't have any state, The node can be
 * defined by passing name and underlying function to this macro.
 */
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(name, func) \
  template <typename F, typename Path = utils::struct_path::Paths<>>      \
  struct name {};                                                         \
  template <typename R, typename... Args, typename Path>                  \
  struct name<R(Args...), Path>                                           \
      : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {    \
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS               \
    callee_ref_t operator()(Args... args) {                               \
      FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(#name, enter)      \
      Path()([](auto &&...sorted) { func(sorted...); },                   \
             std::forward<Args>(args)...);                                \
      FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(name)            \
    }                                                                     \
  };

/**
 * Macro to generate operator() that just invoke child nodes.
 */
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_NOP(name)            \
  callee_ref_t operator()(Args... args) {                          \
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(#name, enter) \
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(name)       \
  }

#endif
