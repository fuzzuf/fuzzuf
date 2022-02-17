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
 * @file update_hierarflow_routines.cpp
 * @brief Definition of HierarFlow routines of Nautilus state update.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <memory>
#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer::routine::update {

/**
 * Types for UpdateState under FuzzLoop
 */
// FuzzLoop <--> UpdateState
using IUpdateState = void(void);
using RUpdateState = NullableRef<HierarFlowCallee<IUpdateState>>;
// UpdateState <--> N/A
using OUpdateState = void(void);

/* update_state */
struct UpdateState : HierarFlowRoutine<IUpdateState, OUpdateState> {
  UpdateState(NautilusState& state) : state(state) {}
  RUpdateState operator()(void);

private:
  NautilusState& state;
};

} // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::update
