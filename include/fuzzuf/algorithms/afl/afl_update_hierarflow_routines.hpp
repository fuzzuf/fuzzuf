/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#pragma once

#include <string>
#include <memory>
#include "fuzzuf/utils/common.hpp"

#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"

#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"

namespace fuzzuf::algorithm::afl::routine::update {

using AFLUpdInputType = bool(const u8*, u32, InplaceMemoryFeedback&, ExitStatusFeedback&);
using AFLUpdCalleeRef = NullableRef<HierarFlowCallee<AFLUpdInputType>>;
using AFLUpdOutputType = void(void);

template<class State>
struct NormalUpdateTemplate
    : public HierarFlowRoutine<
        AFLUpdInputType,
        AFLUpdOutputType
    > {
public:
    NormalUpdateTemplate(State &state);

    AFLUpdCalleeRef operator()(
        const u8*, u32, InplaceMemoryFeedback&, ExitStatusFeedback&);

private:
    State &state;
};

using NormalUpdate = NormalUpdateTemplate<AFLState>;

template<class State>
struct ConstructAutoDictTemplate
    : public HierarFlowRoutine<
        AFLUpdInputType,
        AFLUpdOutputType
    > {
public:
    ConstructAutoDictTemplate(State &state);

    AFLUpdCalleeRef operator()(
        const u8*, u32, InplaceMemoryFeedback&, ExitStatusFeedback&);

private:
    State &state;
};

using ConstructAutoDict = ConstructAutoDictTemplate<AFLState>;

template<class State>
struct ConstructEffMapTemplate
    : public HierarFlowRoutine<
        AFLUpdInputType,
        AFLUpdOutputType
    > {
public:
    ConstructEffMapTemplate(State &state);

    AFLUpdCalleeRef operator()(
        const u8*, u32, InplaceMemoryFeedback&, ExitStatusFeedback&);

private:
    State &state;
};

using ConstructEffMap = ConstructEffMapTemplate<AFLState>;

} // namespace fuzzuf::algorithm::afl::routine::update

#include "fuzzuf/algorithms/afl/templates/afl_update_hierarflow_routines.hpp"
