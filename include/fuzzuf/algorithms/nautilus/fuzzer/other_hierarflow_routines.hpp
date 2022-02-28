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
 * @file other_hierarflow_routines.hpp
 * @brief Definition of unclassified HierarFlow routines of Nautilus.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_OTHER_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_OTHER_HIERARFLOW_ROUTINES_HPP

#include <memory>
#include "fuzzuf/algorithms/nautilus/fuzzer/mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/queue.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other {

using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation;

struct ProcessInput;
struct GenerateInput;

/* fuzz_loop */
struct FuzzLoop : HierarFlowRoutine<void(void), void(void)> {
  FuzzLoop(NautilusState& state) : state(state) {}
  NullableRef<HierarFlowCallee<void(void)>> operator()(void);

private:
  NautilusState& state;
};


/**
 * Types for SelectInput under FuzzLoop
 */
// FuzzLoop <--> SelectInput
using ISelectInput = void(void);
using RSelectInput = NullableRef<HierarFlowCallee<ISelectInput>>;
// SelectInput <--> ProcessInput/GenerateInput
using OSelectInput = void(std::unique_ptr<QueueItem>&);

/* select_input_and_switch */
struct SelectInput : HierarFlowRoutine<ISelectInput, OSelectInput> {
  SelectInput(NautilusState& state,
              const CalleeIndex& process_input_idx,
              const CalleeIndex& generate_input_idx)
    : state (state),
      _process_input_idx (process_input_idx),
      _generate_input_idx (generate_input_idx) {}
  RSelectInput operator()(void);

private:
  NautilusState& state;
  const CalleeIndex& _process_input_idx;
  const CalleeIndex& _generate_input_idx;
};


/**
 * Types for ProcessInput/GenerateInput under SelectInput
 */
// SelectInput <--> ProcessInput
using IProcessInput = OSelectInput;
using RProcessInput = NullableRef<HierarFlowCallee<IProcessInput>>;
// ProcessInput <--> Initialize/ApplyDetMuts/ApplyRandMuts
using OProcessInput = void(QueueItem&);

// SelectInput <--> GenerateInput
using IGenerateInput = OSelectInput;
using RGenerateInput = NullableRef<HierarFlowCallee<IGenerateInput>>;
// Generate <--> ...
using OGenerateInput = void(QueueItem&);

/* process_next_input */
struct ProcessInput : HierarFlowRoutine<IProcessInput, OProcessInput> {
  ProcessInput(NautilusState& state,
               const CalleeIndex&  initialize_state_idx,
               const CalleeIndex& apply_det_muts_idx,
               const CalleeIndex& apply_rand_muts_idx)
    : state (state),
      _initialize_state_idx (initialize_state_idx),
      _apply_det_muts_idx (apply_det_muts_idx),
      _apply_rand_muts_idx (apply_rand_muts_idx) {}
  RProcessInput operator()(std::unique_ptr<QueueItem>&);

private:
  NautilusState& state;
  const CalleeIndex& _initialize_state_idx;
  const CalleeIndex& _apply_det_muts_idx;
  const CalleeIndex& _apply_rand_muts_idx;
};

/* generate_input */
struct GenerateInput : HierarFlowRoutine<IGenerateInput, OGenerateInput> {
  GenerateInput(NautilusState& state) : state(state) {}
  RGenerateInput operator()(std::unique_ptr<QueueItem>&);

private:
  NautilusState& state;
};

} // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other

#endif
