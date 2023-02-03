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

#include <array>
#include <memory>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::aflfast {

// It is reported that an incoming new algorithm inherits this class, thus it is
// impossible to restrict it as final.
class AFLFastFuzzer : public afl::AFLFuzzerTemplate<AFLFastState> {
 public:
  explicit AFLFastFuzzer(std::unique_ptr<AFLFastState>&& state)
      : afl::AFLFuzzerTemplate<AFLFastState>(std::move(state)),
        fuzz_loop(afl::BuildAFLFuzzLoop(
            *afl::AFLFuzzerTemplate<AFLFastState>::state)) {}
  virtual void OneLoop(void) override;

 private:
  void SyncFuzzers();
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

}  // namespace fuzzuf::algorithm::aflfast
