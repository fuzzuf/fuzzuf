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
 * @file fuzzer.hpp
 * @brief Fuzzing loop of Nautilus
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_FUZZER_HPP

#include <memory>
#include <nlohmann/json.hpp>

#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer {

using json = nlohmann::json;

class NautilusFuzzer : public fuzzuf::fuzzer::Fuzzer {
 public:
  explicit NautilusFuzzer(std::unique_ptr<NautilusState>&& state_ref);
  virtual ~NautilusFuzzer();

  void BuildFuzzFlow();
  void CheckPathExistence();
  static void LoadGrammar(Context& ctx, fs::path grammar_path);
  static bool ParseAndAddRule(Context& ctx, std::string nt, json rule,
                              bool recursive = false);

  virtual void OneLoop(void);
  virtual void ReceiveStopSignal(void);
  virtual bool ShouldEnd(void);

 private:
  std::unique_ptr<NautilusState> state;
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

}  // namespace fuzzuf::algorithm::nautilus::fuzzer

#endif
