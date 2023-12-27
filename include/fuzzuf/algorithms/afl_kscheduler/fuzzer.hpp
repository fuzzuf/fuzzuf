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
#ifndef FUZZUF_INCLUDE_ALGORITHM_AFL_KSCHEDULER_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_AFL_KSCHEDULER_FUZZER_HPP

#include <memory>

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/afl_kscheduler/state.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"

namespace fuzzuf::algorithm::afl_kscheduler {

class AFLKSchedulerFuzzer final : public afl::AFLFuzzerTemplate<AFLKSchedulerState> {
 public:
  explicit AFLKSchedulerFuzzer(std::unique_ptr<AFLKSchedulerState>&& state);
  virtual void OneLoop() override;
 private:
  void SyncFuzzers();
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};
}
namespace fuzzuf::algorithm::afl {
template<>
hierarflow::HierarFlowNode<void(void), void(void)> BuildAFLFuzzLoop< afl_kscheduler::AFLKSchedulerState >(
  afl_kscheduler::AFLKSchedulerState &state
);

}  // namespace fuzzuf::algorithm::afl_kscheduler

#endif

