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
 * @file VUzzer.hpp
 * @brief Fuzzing loop of VUzzer.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <array>
#include <memory>
#include <string>
#include <vector>

#include "fuzzuf/algorithms/vuzzer/vuzzer_setting.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_state.hpp"
#include "fuzzuf/executor/pintool_executor.hpp"
#include "fuzzuf/executor/polytracker_executor.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::vuzzer {

class VUzzer : public fuzzer::Fuzzer {
 public:
  explicit VUzzer(std::unique_ptr<VUzzerState> &&state_ref);

  ~VUzzer();

  void PerformDryRun(VUzzerState &state);
  void FillSeeds(VUzzerState &state, u32 size);
  void BuildFuzzFlow(void);
  void OneLoop(void);

  void ReceiveStopSignal(void);
  bool ShouldEnd(void) { return false; }

 private:
  // We need std::unique_ptr because we have to make the construction of these
  // variables "delayed" For example, PinToolExecutor doesn't have the default
  // constructor PinToolExecutor() nor operator=(). So we have no choice but to
  // delay those constructors
  std::unique_ptr<VUzzerState> state;
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

}  // namespace fuzzuf::algorithm::vuzzer
