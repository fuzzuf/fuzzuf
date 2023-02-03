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

#ifndef FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_FUZZER_HPP

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/ijon/ijon_state.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"

namespace fuzzuf::algorithm::ijon {
/**
 * @brief CLI compatible interface for IJON
 */
class IJONFuzzer final : public afl::AFLFuzzerTemplate<IJONState> {
 public:
  explicit IJONFuzzer(std::unique_ptr<IJONState>&& state, u32 ijon_max_offset);
  ~IJONFuzzer();

  void OneLoop(void) override;

 private:
  void BuildFuzzFlow(void);
  bool IjonShouldSchedule(void);
  void SyncFuzzers();

  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
  hierarflow::HierarFlowNode<void(void), void(void)> ijon_fuzz_loop;
  u32 ijon_max_offset;
};

}  // namespace fuzzuf::algorithm::ijon

#endif
