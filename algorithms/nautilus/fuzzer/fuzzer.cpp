/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file nautilus_fuzzer.cpp
 * @brief Fuzzing loop of Nautilus.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/fuzzer/fuzzer.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/update_hierarflow_routines.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer {

/**
 * @fn
 * @brief Construct Nautilus fuzzer
 * @param (state_ref) Reference to the state of Nautilus fuzzer
 */
NautilusFuzzer::NautilusFuzzer(std::unique_ptr<NautilusState>&& state_ref)
  : state(std::move(state_ref)) {
  // TODO: check target binary path
  // TODO: check grammar file path

  // TODO: generate rules using grammar

  // TODO: create output folder

  BuildFuzzFlow();
}

void NautilusFuzzer::BuildFuzzFlow() {
  using fuzzuf::hierarflow::CreateNode;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::update;

  fuzz_loop = CreateNode<FuzzLoop>(*state);

  auto select_input = CreateNode<SelectInput>(*state);
  auto process_input_or = CreateNode<ProcessInput>(*state);

#if 0

  fuzz_loop <<
    select_input << (
      process_input_or
      || generate_input
    )
    || update_state
  );

  process_input << (
    initialize_or << (
      
    )
    || apply_det_muts_or << (
      det_tree_mut
      || splice
      || havoc
      || havoc_recursion
    )
    || applit_rand_muts << (
         splice
      || havoc
      || havoc_recursion
    )
  );
#endif
}

/**
 * @fn
 * @brief Run fuzzing loop once
 */
void NautilusFuzzer::OneLoop(void) {
  fuzz_loop();
}

/**
 * @fn
 * @brief Receive stop signal
 */
void NautilusFuzzer::ReceiveStopSignal(void) {
  // TODO: comment out
  //state->ReceiveStopSignal();
}

/**
 * @fn
 * @brief Check if fuzzing should terminate
 * @return True if fuzzing ends, otherwise false
 */
bool NautilusFuzzer::ShouldEnd(void) {
  return false;
}

/**
 * @fn
 * @brief Destroy this instance
 */
NautilusFuzzer::~NautilusFuzzer() {
}

} // namespace fuzzuf::algorithm::nautilus
