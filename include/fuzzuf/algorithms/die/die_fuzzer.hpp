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
 * @file die_fuzzer.hpp
 * @brief Fuzzing loop of DIE
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/die/die_state.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::die {

class DIEFuzzer final : public afl::AFLFuzzerTemplate<DIEState> {
 public:
  explicit DIEFuzzer(std::unique_ptr<DIEState>&& state)
      : afl::AFLFuzzerTemplate<DIEState>(std::move(state)) {
    BuildFuzzFlow();
  }
  virtual void OneLoop(void) override { fuzz_loop(); }

 private:
  void BuildFuzzFlow();
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

}  // namespace fuzzuf::algorithm::die
