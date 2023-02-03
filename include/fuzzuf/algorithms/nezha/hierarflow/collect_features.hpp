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
 * @file collect_features.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_HIERARFLOW_COLLECT_FEATURES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_HIERARFLOW_COLLECT_FEATURES_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/nezha/executor/collect_features.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::nezha {
/**
 * @class CollectFeatures
 * @brief Calculate features according to specified execution result.
 * "Feature" is a outstanding feature of the execution which has unique ID. In
 * most case, entering a new edge that is not covered by previous executions is
 * a feature. "Features" is a vector of feature. libFuzzer calculate weight of
 * the execution result that affects by features. If ChooseRandomSeed is using
 * non-uniform distribution, input of higher weighted execution result is
 * selected more frequentry. The node takes 5 paths for state, corpus, input,
 * execution result and coverage.
 *
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct CollectFeatures {};
template <typename R, typename... Args, typename Path>
struct CollectFeatures<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param module_offset_ Offset value of feature. if module_offset is 3000 and
   * cov[ 2 ] is non zero value, the feature 3002 is activated.
   */
  CollectFeatures(std::uint32_t module_offset_ = 0)
      : module_offset(module_offset_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("CollectFeatures", enter)
    Path()(
        [&](auto &&...sorted) {
          executor::CollectFeatures(sorted..., module_offset);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(CollectFeatures)
  }

 private:
  std::uint32_t module_offset;
};
namespace standard_order {
template <typename T>
using CollectFeaturesStdArgOrderT =
    decltype(T::state && T::corpus && T::input && T::exec_result &&
             T::coverage);
template <typename F, typename Ord>
using CollectFeatures =
    nezha::CollectFeatures<F, CollectFeaturesStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::nezha

#endif
