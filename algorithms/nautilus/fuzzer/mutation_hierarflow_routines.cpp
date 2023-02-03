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
 * @file mutation_hierarflow_routines.cpp
 * @brief Definition of HierarFlow routines of Nautilus mutation.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/fuzzer/mutation_hierarflow_routines.hpp"

#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation {

/**
 * @fn
 * @brief HierarFlow routine for InitializeState (initialize_state)
 */
RInitializeState InitializeState::operator()(QueueItem& inp) {
  DEBUG_ASSERT(std::holds_alternative<InitState>(inp.state));

  /* Minimize testcase */
  size_t start_index = std::get<InitState>(inp.state);
  size_t end_index = start_index + 200;

  if (state.Minimize(inp, start_index, end_index)) {
    inp.state = DetState(0, 0);
  } else {
    inp.state = InitState(end_index);
  }

  return GoToParent();  // back to process_next_input
}

/**
 * @fn
 * @brief HierarFlow routine for ApplyDetMuts (apply_det_muts)
 */
RApplyDetMuts ApplyDetMuts::operator()(QueueItem& inp) {
  DEBUG_ASSERT(std::holds_alternative<DetState>(inp.state));

  /* Rules, Splice, Havoc, and HavocRecursion */
  CallSuccessors(inp);  // mut_rules

  return GoToParent();  // back to process_next_input
}

/**
 * @fn
 * @brief HierarFlow routine for ApplyRandMuts (apply_rand_muts)
 */
RApplyRandMuts ApplyRandMuts::operator()(QueueItem& inp) {
  DEBUG_ASSERT(std::holds_alternative<RandomState>(inp.state));

  /* Splice, Havoc, and HavocRecursion */
  CallSuccessors(inp);  // splice

  return GoToParent();  // back to process_next_input
}

/**
 * @fn
 * @brief HierarFlow routine for MutRules (mut_rules)
 */
RMutRules MutRules::operator()(QueueItem& inp) {
  auto [cycle, start_index] = std::get<DetState>(inp.state);
  size_t end_index = start_index + 1;

  /* Deterministic tree mutation (Rules Mutation) */
  if (state.DeterministicTreeMutation(inp, start_index, end_index)) {
    if (cycle == state.setting->number_of_deterministic_mutations) {
      inp.state = RandomState();

    } else {
      inp.state = DetState(cycle + 1, 0);
    }

  } else {
    inp.state = DetState(cycle, end_index);
  }

  return GoToDefaultNext();
}

/**
 * @fn
 * @brief HierarFlow routine for Splice (splice)
 */
RMutSplice MutSplice::operator()(QueueItem& inp) {
  FTesterMut tester = [this](TreeMutation& t, Context& ctx) -> bool {
    return this->state.RunOnWithDedup(t, ExecutionReason::Splice, ctx);
  };

  for (size_t i = 0; i < 100; i++) {
    // TODO: Wait lock for cks when threaded
    state.mutator.MutSplice(inp.tree, state.ctx, state.cks, tester);
  }

  return GoToDefaultNext();
}

/**
 * @fn
 * @brief HierarFlow routine for Havoc (havoc)
 */
RMutHavoc MutHavoc::operator()(QueueItem& inp) {
  FTesterMut tester = [this](TreeMutation& t, Context& ctx) {
    this->state.RunOnWithDedup(t, ExecutionReason::Havoc, ctx);
  };

  for (size_t i = 0; i < 100; i++) {
    state.mutator.MutRandom(inp.tree, state.ctx, tester);
  }

  return GoToDefaultNext();
}

/**
 * @fn
 * @brief HierarFlow routine for HavocRec (havoc_rec)
 */
RMutHavocRec MutHavocRec::operator()(QueueItem& inp) {
  if (inp.recursions) {
    /* If input has recursions */

    FTesterMut tester = [this](TreeMutation& t, Context& ctx) {
      this->state.RunOnWithDedup(t, ExecutionReason::HavocRec, ctx);
    };

    for (size_t i = 0; i < 20; i++) {
      state.mutator.MutRandomRecursion(inp.tree, inp.recursions.value(),
                                       state.ctx, tester);
    }
  }

  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation
