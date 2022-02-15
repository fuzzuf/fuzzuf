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
#pragma once

#include <memory>
#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/queue.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other {

/* fuzz_loop */
struct FuzzLoop : HierarFlowRoutine<void(void), void(void)> {
  FuzzLoop(NautilusState& state) : state(state) {}
  NullableRef<HierarFlowCallee<void(void)>> operator()(void);

private:
  NautilusState& state;
};

/**
 * Types for SelectInput and UpdateState under FuzzLoop
 */
// FuzzLoop <--> SelectInput
using ISelectInput = void(void);
using RSelectInput = NullableRef<HierarFlowCallee<ISelectInput>>;
// SelectInput <--> ProcessInput/GenerateInput
using OSelectInput = void(std::optional<std::reference_wrapper<QueueItem>>);
// FuzzLoop <--> UpdateState
using IUpdateState = void(void);
using RUpdateState = NullableRef<HierarFlowCallee<IUpdateState>>;
// UpdateState <--> N/A
using OUpdateState = void(void);

/* select_input */
struct SelectInput : HierarFlowRoutine<ISelectInput, OSelectInput> {
  SelectInput(NautilusState& state) : state(state) {}
  RSelectInput operator()(void);

private:
  NautilusState& state;
};

/* update_state */
struct UpdateState : HierarFlowRoutine<IUpdateState, OUpdateState> {
  UpdateState(NautilusState& state) : state(state) {}
  RUpdateState operator()(void);

private:
  NautilusState& state;
};


/**
 * Types for ProcessInput and GenerateInput under SelectInput
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
using OGenerateInput = void(void);

/* process_input_or */
struct ProcessInput : HierarFlowRoutine<IProcessInput, OProcessInput> {
  ProcessInput(NautilusState& state) : state(state) {}
  RProcessInput operator()(
    std::optional<std::reference_wrapper<QueueItem>> inp
  );

private:
  NautilusState& state;
};

/* generate_input */
struct GenerateInput : HierarFlowRoutine<IGenerateInput, OGenerateInput> {
  GenerateInput(NautilusState& state) : state(state) {}
  RGenerateInput operator()(
    std::optional<std::reference_wrapper<QueueItem>>
  );

private:
  NautilusState& state;
};

} // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other
