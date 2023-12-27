/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_REZZUF_KSCHEDULER_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_REZZUF_KSCHEDULER_FUZZER_HPP

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

hierarflow::HierarFlowNode<void(void), void(void)> BuildFuzzLoop(
    State& state);

class Fuzzer final : public afl::AFLFuzzerTemplate<State> {
 public:
  explicit Fuzzer(std::unique_ptr<State>&& state)
      : afl::AFLFuzzerTemplate<State>(std::move(state)) {
    fuzz_loop = BuildFuzzLoop(*this->state);
  }

  virtual void OneLoop(void) override;

  const std::unique_ptr<State> &GetState() const {
    return state;
  }
 private:
  void SyncFuzzers();
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

}  // namespace fuzzuf::algorithm::rezzuf_kscheduler

#endif

