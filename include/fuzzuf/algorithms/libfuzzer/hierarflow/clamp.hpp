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
 * @file clamp.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_CLAMP_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_CLAMP_HPP
#include <tuple>

#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class Clamp
 * @brief Clamp the value specified by the Path by min and max.
 * The node takes 1 path for the value.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct Clamp {};
template <typename R, typename... Args, typename Path>
struct Clamp<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
  using value_type = utils::type_traits::RemoveCvrT<
      utils::struct_path::PointedTypeT<R(Args...), Path>>;
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param min Minimum value
   * @param max Maximum value
   */
  Clamp(const value_type &min_, const value_type &max_)
      : min(min_), max(max_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("Clamp", enter)
    Path()(
        [&](auto &&to) {
          if (to < min) to = min;
          if (to > max) to = max;
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(Clamp)
  }

 private:
  value_type min;
  value_type max;
};

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
