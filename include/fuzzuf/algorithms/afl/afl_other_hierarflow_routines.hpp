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
#pragma once

#include <memory>

#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::afl::routine::other {

// middle nodes(steps done before and after actual mutations)

template <class State>
struct CullQueueTemplate
    : public hierarflow::HierarFlowRoutine<void(void), void(void)> {
 public:
  CullQueueTemplate(State &state);

  utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>> operator()(void);

 private:
  State &state;
};

using CullQueue = CullQueueTemplate<AFLState>;

template <class State>
struct SelectSeedTemplate
    : public hierarflow::HierarFlowRoutine<
          void(void), bool(std::shared_ptr<typename State::OwnTestcase>)> {
 public:
  SelectSeedTemplate(State &state);

  utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>> operator()(void);

 private:
  State &state;
  u64 prev_queued = 0;
};

using SelectSeed = SelectSeedTemplate<AFLState>;

template <class State>
using AFLMidInputType = bool(std::shared_ptr<typename State::OwnTestcase>);

template <class State>
using AFLMidCalleeRef =
    utils::NullableRef<hierarflow::HierarFlowCallee<AFLMidInputType<State>>>;

template <class State>
using AFLMidOutputType = bool(AFLMutatorTemplate<State> &);

template <class State>
struct ConsiderSkipMutTemplate
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<State>,
                                           AFLMidOutputType<State>> {
 public:
  ConsiderSkipMutTemplate(State &state);

  AFLMidCalleeRef<State> operator()(
      std::shared_ptr<typename State::OwnTestcase>);

 private:
  State &state;
};

using ConsiderSkipMut = ConsiderSkipMutTemplate<AFLState>;

template <class State>
struct RetryCalibrateTemplate
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<State>,
                                           AFLMidOutputType<State>> {
 public:
  RetryCalibrateTemplate(State &state, AFLMidCalleeRef<State> abandon_entry);

  AFLMidCalleeRef<State> operator()(
      std::shared_ptr<typename State::OwnTestcase>);

 private:
  State &state;
  AFLMidCalleeRef<State> abandon_entry;
};

using RetryCalibrate = RetryCalibrateTemplate<AFLState>;

template <class State>
struct TrimCaseTemplate
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<State>,
                                           AFLMidOutputType<State>> {
 public:
  TrimCaseTemplate(State &state, AFLMidCalleeRef<State> abandon_entry);

  AFLMidCalleeRef<State> operator()(
      std::shared_ptr<typename State::OwnTestcase>);

 private:
  State &state;
  AFLMidCalleeRef<State> abandon_entry;
};

using TrimCase = TrimCaseTemplate<AFLState>;

template <class State>
struct CalcScoreTemplate
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<State>,
                                           AFLMidOutputType<State>> {
 public:
  CalcScoreTemplate(State &state);

  AFLMidCalleeRef<State> operator()(
      std::shared_ptr<typename State::OwnTestcase>);

 private:
  State &state;
};

using CalcScore = CalcScoreTemplate<AFLState>;

template <class State>
struct ApplyDetMutsTemplate
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<State>,
                                           AFLMidOutputType<State>> {
 public:
  ApplyDetMutsTemplate(State &state, AFLMidCalleeRef<State> abandon_entry);

  AFLMidCalleeRef<State> operator()(
      std::shared_ptr<typename State::OwnTestcase>);

 private:
  State &state;
  AFLMidCalleeRef<State> abandon_entry;
};

using ApplyDetMuts = ApplyDetMutsTemplate<AFLState>;

template <class State>
struct ApplyRandMutsTemplate
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<State>,
                                           AFLMidOutputType<State>> {
 public:
  ApplyRandMutsTemplate(State &state, AFLMidCalleeRef<State> abandon_entry);

  AFLMidCalleeRef<State> operator()(
      std::shared_ptr<typename State::OwnTestcase>);

 private:
  State &state;
  AFLMidCalleeRef<State> abandon_entry;
};

using ApplyRandMuts = ApplyRandMutsTemplate<AFLState>;

template <class State>
struct AbandonEntryTemplate
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<State>,
                                           AFLMidOutputType<State>> {
 public:
  AbandonEntryTemplate(State &state);

  AFLMidCalleeRef<State> operator()(
      std::shared_ptr<typename State::OwnTestcase>);

 private:
  State &state;
};

using AbandonEntry = AbandonEntryTemplate<AFLState>;

template <class State>
struct ExecutePUTTemplate
    : public hierarflow::HierarFlowRoutine<
          bool(const u8 *, u32),
          bool(const u8 *, u32, feedback::InplaceMemoryFeedback &,
               feedback::ExitStatusFeedback &)> {
 public:
  ExecutePUTTemplate(State &state);

  utils::NullableRef<hierarflow::HierarFlowCallee<bool(const u8 *, u32)>>
  operator()(const u8 *, u32);

 private:
  State &state;
};

using ExecutePUT = ExecutePUTTemplate<AFLState>;

}  // namespace fuzzuf::algorithm::afl::routine::other

#include "fuzzuf/algorithms/afl/templates/afl_other_hierarflow_routines.hpp"
