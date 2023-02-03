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
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_MUTATION_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_MUTATION_HIERARFLOW_ROUTINES_HPP

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
using RInitializeState =
    utils::NullableRef<hierarflow::HierarFlowCallee<IInitializeState>>;
// InitializeState <--> N/A
using OInitializeState = void(void);

// ProcessInput <--> ApplyDetMuts
using IApplyDetMuts = OProcessInput;
using RApplyDetMuts =
    utils::NullableRef<hierarflow::HierarFlowCallee<IApplyDetMuts>>;
// ApplyDetMuts <--> MutSplice/MutHavoc/MutHavocRecursion
using OApplyDetMuts = void(QueueItem&);

// ProcessInput <--> ApplyRandMuts
using IApplyRandMuts = OProcessInput;
using RApplyRandMuts =
    utils::NullableRef<hierarflow::HierarFlowCallee<IApplyRandMuts>>;
// ApplyRandMuts <--> MutSplice/MutHavoc/MutHavocRecursion
using OApplyRandMuts = void(QueueItem&);

/* initialize_state */
struct InitializeState
    : hierarflow::HierarFlowRoutine<IInitializeState, OInitializeState> {
  InitializeState(NautilusState& state) : state(state) {}
  RInitializeState operator()(QueueItem&);

 private:
  NautilusState& state;
};

/* apply_det_muts */
struct ApplyDetMuts
    : hierarflow::HierarFlowRoutine<IApplyDetMuts, OApplyDetMuts> {
  ApplyDetMuts(NautilusState& state) : state(state) {}
  RApplyDetMuts operator()(QueueItem&);

 private:
  NautilusState& state;
};

/* apply_rand_muts */
struct ApplyRandMuts
    : hierarflow::HierarFlowRoutine<IApplyRandMuts, OApplyRandMuts> {
  ApplyRandMuts(NautilusState& state) : state(state) {}
  RApplyRandMuts operator()(QueueItem&);

 private:
  NautilusState& state;
};

/**
 * Types for Splice/Havoc/HavocRec under ApplyDetMuts/ApplyRandMuts
 */
// ApplyDetMuts <--> MutRules
using IMutRules = OApplyDetMuts;
using RMutRules = utils::NullableRef<hierarflow::HierarFlowCallee<IMutRules>>;
// MutRules <--> N/A
using OMutRules = void(void);

// ApplyDetMuts/ApplyRandMuts <--> Splice
using IMutSplice = OApplyDetMuts;  // == OApplyRandMuts
using RMutSplice = utils::NullableRef<hierarflow::HierarFlowCallee<IMutSplice>>;
// MutSplice <--> N/A
using OMutSplice = void(void);

// ApplyDetMuts/ApplyRandMuts <--> MutHavoc
using IMutHavoc = OApplyDetMuts;  // == OApplyRandMuts
using RMutHavoc = utils::NullableRef<hierarflow::HierarFlowCallee<IMutHavoc>>;
// MutHavoc <--> N/A
using OMutHavoc = void(void);

// ApplyDetMuts/ApplyRandMuts <--> HavocRec
using IMutHavocRec = OApplyDetMuts;  // == OApplyRandMuts
using RMutHavocRec =
    utils::NullableRef<hierarflow::HierarFlowCallee<IMutHavocRec>>;
// Havoc <--> N/A
using OMutHavocRec = void(void);

/* rules mutation */
struct MutRules : hierarflow::HierarFlowRoutine<IMutRules, OMutRules> {
  MutRules(NautilusState& state) : state(state) {}
  RMutRules operator()(QueueItem&);

 private:
  NautilusState& state;
};

/* splice */
struct MutSplice : hierarflow::HierarFlowRoutine<IMutSplice, OMutSplice> {
  MutSplice(NautilusState& state) : state(state) {}
  RMutSplice operator()(QueueItem&);

 private:
  NautilusState& state;
};

/* havoc */
struct MutHavoc : hierarflow::HierarFlowRoutine<IMutHavoc, OMutHavoc> {
  MutHavoc(NautilusState& state) : state(state) {}
  RMutHavoc operator()(QueueItem&);

 private:
  NautilusState& state;
};

/* havoc_rec */
struct MutHavocRec : hierarflow::HierarFlowRoutine<IMutHavocRec, OMutHavocRec> {
  MutHavocRec(NautilusState& state) : state(state) {}
  RMutHavocRec operator()(QueueItem&);

 private:
  NautilusState& state;
};

}  // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation

#endif
