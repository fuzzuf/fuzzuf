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
#pragma once

#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"

namespace fuzzuf::algorithm::afl {

template <class State>
class AFLFuzzerTemplate : public fuzzer::Fuzzer {
 public:
  explicit AFLFuzzerTemplate(std::unique_ptr<State>&& state);
  virtual ~AFLFuzzerTemplate();

  virtual void OneLoop(void) = 0;
  virtual void ReceiveStopSignal(void);
  virtual bool ShouldEnd(void);

 protected:
  std::unique_ptr<State> state;
};

template <class State>
hierarflow::HierarFlowNode<void(void), void(void)> BuildAFLFuzzLoop(State&);

class AFLFuzzer final : public AFLFuzzerTemplate<AFLState> {
 public:
  explicit AFLFuzzer(std::unique_ptr<AFLState>&& state)
      : AFLFuzzerTemplate<AFLState>(std::move(state)),
        fuzz_loop(BuildAFLFuzzLoop(*AFLFuzzerTemplate<AFLState>::state)) {}
  virtual void OneLoop(void) override;

 private:
  void SyncFuzzers();
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

}  // namespace fuzzuf::algorithm::afl

#include "fuzzuf/algorithms/afl/templates/afl_fuzzer.hpp"
