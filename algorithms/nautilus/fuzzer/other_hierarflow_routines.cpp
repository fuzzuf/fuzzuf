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
 * @file other_hierarflow_routines.cpp
 * @brief Definition of unclassified HierarFlow routines of Nautilus.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <memory>
#include <variant>
#include "fuzzuf/algorithms/nautilus/fuzzer/other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/queue.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other {

/**
 * @fn
 * @brief HierarFlow routine for FuzzLoop (fuzz_loop)
 */
NullableRef<HierarFlowCallee<void(void)>> FuzzLoop::operator()(void) {
  puts("[DEBUG] FuzzLoop");
  CallSuccessors(); // select_input
  return GoToDefaultNext();
}

/**
 * @fn
 * @brief HierarFlow routine for SelectInput (select_input)
 */
RSelectInput SelectInput::operator()(void) {
  puts("[DEBUG] SelectInput");
  std::optional<QueueItem> inp;

  if (state.queue.IsEmpty()) {
    inp = std::nullopt;
  } else {
    // TODO: Use lock when multi-threaded
    inp = state.queue.Pop();
  }

  CallSuccessors(inp); // process_input_or
  return GoToDefaultNext(); // update_state
}

/**
 * @fn
 * @brief HierarFlow routine for UpdateState (update_state)
 */
RUpdateState UpdateState::operator()(void) {
  puts("[DEBUG] UpdateState");

  // TODO: Lock state when multi-threaded

  return GoToDefaultNext();
}


/**
 * @fn
 * @brief HierarFlow routine for ProcessInput (process_input_or)
 * @param (inp) Queue item to process
 */
RProcessInput ProcessInput::operator()(std::optional<QueueItem> inp) {
  puts("[DEBUG] ProcessInput");

  if (inp) {

    /* Corpus exists. Mutate input. */
    CallSuccessors(inp.value()); // initialize_or

    /* Mark as finished */
    state.queue.Finished(std::move(inp.value()));

    return GoToParent(); // back to select_input

  } else {

    /* Queue is empty. Generate new input. */
    return GoToDefaultNext(); // generate_input

  }
}

/**
 * @fn
 * @brief HierarFlow routine for GenerateInput (generate_input)
 * @param (inp) Empty item. Not used.
 */
RGenerateInput GenerateInput::operator()(std::optional<QueueItem>) {
  puts("[DEBUG] GenerateInput");

  for (size_t i = 0; i < state.setting->number_of_generate_inputs; i++) {
    /* Generate random seed and run it */
    const NTermID& nonterm = state.ctx.NTID("START");
    size_t len = state.ctx.GetRandomLenForNT(nonterm);
    Tree tree = state.ctx.GenerateTreeFromNT(nonterm, len);

    /* Run input without duplication */
    state.RunOnWithDedup(tree, ExecutionReason::Gen, state.ctx);
  }

  state.queue.NewRound();

  return GoToDefaultNext(); // back to select_input
}

} // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other
