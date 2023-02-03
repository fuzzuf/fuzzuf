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

#include <memory>
#include <string>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::cli {

template <class State>
class AFLFuzzerStub : public fuzzuf::fuzzer::Fuzzer {
 public:
  // Make member variables public to go easy way since it is for testing
  std::unique_ptr<State> state;

  // Arguments for a constructor must be the same as that of AFLFuzzer
  AFLFuzzerStub(std::unique_ptr<State>&& state) : state(std::move(state)) {}

  void ReceiveStopSignal(void) {}
  bool ShouldEnd(void) { return false; }
};

}  // namespace fuzzuf::cli
