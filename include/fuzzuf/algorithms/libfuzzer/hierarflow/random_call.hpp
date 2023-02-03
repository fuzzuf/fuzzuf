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
 * @file random_call.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_RANDOM_CALL_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_RANDOM_CALL_HPP
#include <utility>

#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class RandomCall
 * @brief Invoke randomly selected one of the child nodes.
 * If the node doesn't have any child nodes, nothing are invoked.
 * This node modifies flow.
 * The node takes 1 path for RNG.
 *
 * Since common random call implementation located in HierarFlow/Utility.hpp
 * doesn't have ability to select RNG instance, this libFuzzer implementation
 * cannot replace RandomCall to common version. In this implementation, RNG
 * algoritm must be selectable, due to some tests require RNG that produce
 * deterministic values.
 *
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct RandomCall {};
template <typename R, typename... Args, typename Path>
class RandomCall<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_NOP(RandomCall)
 private:
  /**
   * Retrieve one random value, select one child node and invoke it.
   * @param args Arguments
   * @return result of child node
   */
  virtual R CallSuccessors(Args... args) override {
    const auto end = base_type::UnwrapCurrentLinkedNodeRef().succ_nodes.size();
    if (end != 0u) {
      unsigned int n = 0u;
      Path()([&](auto &&rng) { n = random_value(rng, end); },
             std::forward<Args>(args)...);
      {
        utils::NullableRef<hierarflow::HierarFlowCallee<output_cb_t>> succ_ref =
            *base_type::UnwrapCurrentLinkedNodeRef().succ_nodes[n];
        auto &succ = succ_ref.value().get();
        auto next_succ_ref = succ(std::forward<Args>(args)...);
        succ_ref.swap(next_succ_ref);
      }
    }
    if constexpr (std::is_same_v<R, void>) {
      return;
    } else {
      return base_type::UnwrapCurrentLinkedNodeRef().resp_val;
    }
  }
};
namespace standard_order {
template <typename T>
using RandomCallStdArgOrderT = decltype(T::rng);
template <typename F, typename Ord>
using RandomCall = libfuzzer::RandomCall<F, RandomCallStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
