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
 * @file mutation_hierarflow_routines.cpp
 * @brief Definition of HierarFlow routines of Nautilus mutation.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <memory>
#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation {

using OProcessInput = void(QueueItem&);

/**
 * Types for InitializeState/ApplyDetMuts/ApplyRandMuts under ProcessInput
 */
// ProcessInput <--> InitializeState
using IInitializeState = OProcessInput;
using RInitializeState = NullableRef<HierarFlowCallee<IInitializeState>>;
// InitializeState <--> N/A
using OInitializeState = void(void);

// ProcessInput <--> ApplyDetMuts
using IApplyDetMuts = OProcessInput;
using RApplyDetMuts = NullableRef<HierarFlowCallee<IApplyDetMuts>>;
// ApplyDetMuts <--> MutSplice/MutHavoc/MutHavocRecursion
using OApplyDetMuts = void(QueueItem&);

// ProcessInput <--> ApplyRandMuts
using IApplyRandMuts = OProcessInput;
using RApplyRandMuts = NullableRef<HierarFlowCallee<IApplyRandMuts>>;
// ApplyRandMuts <--> MutSplice/MutHavoc/MutHavocRecursion
using OApplyRandMuts = void(QueueItem&);

/* initialize_state_or */
struct InitializeState : HierarFlowRoutine<IInitializeState, OInitializeState> {
  InitializeState(NautilusState& state) : state(state) {}
  RInitializeState operator()(QueueItem&);

private:
  NautilusState& state;
};

/* apply_det_muts_or */
struct ApplyDetMuts : HierarFlowRoutine<IApplyDetMuts, OApplyDetMuts> {
  ApplyDetMuts(NautilusState& state) : state(state) {}
  RApplyDetMuts operator()(QueueItem&);

private:
  NautilusState& state;
};

/* apply_rand_muts */
struct ApplyRandMuts : HierarFlowRoutine<IApplyRandMuts, OApplyRandMuts> {
  ApplyRandMuts(NautilusState& state) : state(state) {}
  RApplyRandMuts operator()(QueueItem&);

private:
  NautilusState& state;
};

/**
 * Types for Splice/Havoc/HavocRec under ApplyDetMuts/ApplyRandMuts
 */
// ApplyDetMuts/ApplyRandMuts <--> Splice
using IMutSplice = OApplyDetMuts; // == OApplyRandMuts
using RMutSplice = NullableRef<HierarFlowCallee<IMutSplice>>;
// MutSplice <--> N/A
using OMutSplice = void(void);

// ApplyDetMuts/ApplyRandMuts <--> MutHavoc
using IMutHavoc = OApplyDetMuts; // == OApplyRandMuts
using RMutHavoc = NullableRef<HierarFlowCallee<IMutHavoc>>;
// MutHavoc <--> N/A
using OMutHavoc = void(void);

// ApplyDetMuts/ApplyRandMuts <--> HavocRec
using IMutHavocRec = OApplyDetMuts; // == OApplyRandMuts
using RMutHavocRec = NullableRef<HierarFlowCallee<IMutHavocRec>>;
// Havoc <--> N/A
using OMutHavocRec = void(void);

/* splice */
struct MutSplice : HierarFlowRoutine<IMutSplice, OMutSplice> {
  MutSplice(NautilusState& state) : state(state) {}
  RMutSplice operator()(QueueItem&);

private:
  NautilusState& state;
};

/* havoc */
struct MutHavoc : HierarFlowRoutine<IMutHavoc, OMutHavoc> {
  MutHavoc(NautilusState& state) : state(state) {}
  RMutHavoc operator()(QueueItem&);

private:
  NautilusState& state;
};

/* havoc_rec */
struct MutHavocRec : HierarFlowRoutine<IMutHavocRec, OMutHavocRec> {
  MutHavocRec(NautilusState& state) : state(state) {}
  RMutHavocRec operator()(QueueItem&);

private:
  NautilusState& state;
};

} // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation
