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
  CallSuccessors(); // select_input

  state.cycles_done++;

  return GoToDefaultNext();
}

/**
 * @fn
 * @brief HierarFlow routine for SelectInput (select_input_and_switch)
 */
RSelectInput SelectInput::operator()(void) {
  std::unique_ptr<QueueItem> inp;

  auto& node = this->UnwrapCurrentLinkedNodeRef();
  auto& succ_nodes = node.succ_nodes;

  if (succ_nodes.size() != 2) {
    /* We call either process_next_input or generate_input */
    throw exceptions::wrong_hierarflow_usage(
      "Invalid number of children for SelectInput",
      __FILE__, __LINE__
    );
  }

  if (state.queue.IsEmpty()) {
    /* If queue is empty, generate a new testcase */
    (*succ_nodes[1])(inp); // generate_input (inp is invalid here)

  } else {
    /* If queue is not empty, pop a testcase and mutate it by ProcessInput */
    inp = std::make_unique<QueueItem>(state.queue.Pop());
    (*succ_nodes[1])(inp); // process_next_input
  }

  return GoToDefaultNext(); // update_state
}

/**
 * @fn
 * @brief HierarFlow routine for ProcessInput (process_chosen_input_or)
 * @param (inp) Queue item to process
 */
RProcessInput ProcessInput::operator()(std::unique_ptr<QueueItem>& inp) {
  auto& node = this->UnwrapCurrentLinkedNodeRef();
  auto& succ_nodes = node.succ_nodes;

  if (succ_nodes.size() != 3) {
    /* We need initialize_state, apply_det_muts, and apply_rand_muts */
    throw exceptions::wrong_hierarflow_usage(
      "Invalid number of children for ProcessInput",
      __FILE__, __LINE__
    );
  }

  /* Call child node according to the state */
  if (std::holds_alternative<InitState>((*inp).state)) {
    (*succ_nodes[0])(*inp); // initialize_state

  } else if (std::holds_alternative<DetState>((*inp).state)) {
    (*succ_nodes[1])(*inp); // apply_det_muts

  } else if (std::holds_alternative<RandomState>((*inp).state)) {
    (*succ_nodes[2])(*inp); // apply_rand_muts

  } else {
    throw exceptions::wrong_hierarflow_usage(
      "Unexpected input state encountered in ProcessInput",
      __FILE__, __LINE__
    );
  }

  /* Mark as finished.
     We use `std::move` because `inp` will never be used after this. */
  state.queue.Finished(std::move(*inp));

  return GoToParent(); // back to select_input_and_switch
}

/**
 * @fn
 * @brief HierarFlow routine for GenerateInput (generate_input)
 * @param (inp) Empty item. Not used.
 */
RGenerateInput GenerateInput::operator()(std::unique_ptr<QueueItem>&) {
  for (size_t i = 0; i < state.setting->number_of_generate_inputs; i++) {
    /* Generate random seed and run it */
    const NTermID& nonterm = state.ctx.NTID("START");
    size_t len = state.ctx.GetRandomLenForNT(nonterm);
    Tree tree = state.ctx.GenerateTreeFromNT(nonterm, len);

    /* Run input without duplication */
    state.RunOnWithDedup(tree, ExecutionReason::Gen, state.ctx);
  }

  state.queue.NewRound();

  return GoToDefaultNext(); // back to select_input_and_switch
}

} // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other
