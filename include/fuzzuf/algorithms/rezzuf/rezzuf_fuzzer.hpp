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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_REZZUF_REZZUF_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_REZZUF_REZZUF_FUZZER_HPP

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_state.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"

namespace fuzzuf::algorithm::rezzuf {

hierarflow::HierarFlowNode<void(void), void(void)> BuildFuzzLoop(
    RezzufState& state);

class RezzufFuzzer final : public afl::AFLFuzzerTemplate<RezzufState> {
 public:
  explicit RezzufFuzzer(std::unique_ptr<RezzufState>&& state)
      : afl::AFLFuzzerTemplate<RezzufState>(std::move(state)) {
    fuzz_loop = BuildFuzzLoop(*this->state);
  }

  virtual void OneLoop(void) override;

 private:
  void SyncFuzzers();
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

}  // namespace fuzzuf::algorithm::rezzuf

#endif
