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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_AFLPLUSPLUS_AFLPLUSPLUS_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_AFLPLUSPLUS_AFLPLUSPLUS_FUZZER_HPP

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_state.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::aflplusplus {

class AFLplusplusFuzzer final
    : public afl::AFLFuzzerTemplate<AFLplusplusState> {
 public:
  explicit AFLplusplusFuzzer(std::unique_ptr<AFLplusplusState>&& state)
      : afl::AFLFuzzerTemplate<AFLplusplusState>(std::move(state)),
        fuzz_loop(afl::BuildAFLFuzzLoop(
            *afl::AFLFuzzerTemplate<AFLplusplusState>::state)) {}
  virtual void OneLoop(void) override;

 private:
  void SyncFuzzers();
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

}  // namespace fuzzuf::algorithm::aflplusplus

#endif
