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
 * @file choose_random_seed.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_RANDOM_CHOICE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_RANDOM_CHOICE_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/libfuzzer/select_seed.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::libfuzzer {

template <typename T>
using ChooseRandomSeedStdArgOrderT =
    decltype(T::state && T::corpus && T::rng && T::input && T::exec_result);
/**
 * @class ChooseRandomSeed
 * @brief Select one input from corpus randomly and copy it to the specified
 * value. This Node use the corpus specified by first element of Path and copy
 * input to value specifed by second element of Path. The node takes 5 path for
 * state, corpus, RNG, input and execution result.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct ChooseRandomSeed {};
template <typename R, typename... Args, typename Path>
struct ChooseRandomSeed<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<bool(Args...), bool(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @param uniform_dist_
   * If true, all inputs in the corpus are selected in same probability.
   * Otherwise, inputs are weighted by features.
   */
  ChooseRandomSeed(bool uniform_dist_) : uniform_dist(uniform_dist_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("ChooseRandomSeed", enter)
    Path()(
        [&](auto &&...sorted) {
          select_seed::SelectSeed(sorted..., uniform_dist);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(ChooseRandomSeed)
  }

 private:
  bool uniform_dist;
};
namespace standard_order {
template <typename T>
using ChooseRandomSeedStdArgOrderT =
    decltype(T::state && T::corpus && T::rng && T::input && T::exec_result);
template <typename F, typename Ord>
using ChooseRandomSeed =
    libfuzzer::ChooseRandomSeed<F, ChooseRandomSeedStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
