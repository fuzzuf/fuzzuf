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

#ifndef FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_HIERARFLOW_ROUTINES_HPP

#include <memory>

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/ijon/ijon_state.hpp"

namespace fuzzuf::algorithm::ijon::routine {

using IJONMutator = afl::AFLMutatorTemplate<IJONState>;

namespace other {

/**
 * @struct
 * A HierarFlowRoutine for IJON that selects a seed to be mutated.
 */
struct SelectSeed 
    : public HierarFlowRoutine<
        void(void),
        bool(IJONMutator&)
      > {
public:
    SelectSeed(IJONState &state);

    NullableRef<HierarFlowCallee<void(void)>> operator()(void);

private:
    IJONState &state;
};

using IJONMidCalleeRef = afl::routine::other::AFLMidCalleeRef<IJONState>;
using IJONMidInputType = afl::routine::other::AFLMidInputType<IJONState>;

/**
 * @struct
 * A HierarFlowRoutine for IJON that prints the message that IJONFuzzer is delegating to AFL now.
 * This message is just for keeping compatibile with the original implementation.
 */
struct PrintAflIsSelected
    : public HierarFlowRoutine<
        IJONMidInputType,
        void(void) // has no successors
      > {
public:
    PrintAflIsSelected(void);

    IJONMidCalleeRef operator()(std::shared_ptr<IJONTestcase>);
};

} // namespace other

namespace mutation {

using IJONMidCalleeRef = afl::routine::other::AFLMidCalleeRef<IJONState>;
using IJONMidInputType = afl::routine::other::AFLMidInputType<IJONState>;
using IJONMutCalleeRef = afl::routine::mutation::AFLMutCalleeRef<IJONState>;

/**
 * @struct
 * A HierarFlowRoutine for IJON that calls havoc with custom hyperparameters.
 */
struct MaxHavoc : public afl::routine::mutation::HavocBaseTemplate<IJONState> {
public:
    MaxHavoc(IJONState &state);

    IJONMutCalleeRef operator()(IJONMutator& mutator);
};

} // namespace mutation

namespace update {

using IJONUpdCalleeRef = afl::routine::update::AFLUpdCalleeRef;
using IJONUpdInputType = afl::routine::update::AFLUpdInputType;
using IJONUpdOutputType = afl::routine::update::AFLUpdOutputType;

/**
 * @struct
 * A HierarFlowRoutine for IJON that updates the internal state of IJON.
 */
struct UpdateMax
    : public HierarFlowRoutine<
        IJONUpdInputType,
        IJONUpdOutputType
    > {
public:
    UpdateMax(IJONState &state);

    IJONUpdCalleeRef operator()(
        const u8*, u32, InplaceMemoryFeedback&, ExitStatusFeedback&);

private:
    IJONState &state;
};

} // namespace update

} // namespace fuzzuf::algorithm::ijon::routine

#endif
