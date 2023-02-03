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

#include "fuzzuf/algorithms/vuzzer/vuzzer_state.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_testcase.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_util.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::vuzzer::routine::other {

// the head node(the fuzzing loop starts from execution in VUzzer)

struct FuzzLoop : public hierarflow::HierarFlowRoutine<void(void), void(void)> {
 public:
  FuzzLoop(VUzzerState &state);

  utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>> operator()(void);

 private:
  VUzzerState &state;
};

// middle nodes(steps done before and after actual mutations)

using VUzzerMidInputType = void(void);
using VUzzerMidCalleeRef =
    utils::NullableRef<hierarflow::HierarFlowCallee<VUzzerMidInputType>>;
using VUzzerMidOutputType = void(void);

struct DecideKeep : public hierarflow::HierarFlowRoutine<VUzzerMidInputType,
                                                         VUzzerMidOutputType> {
 public:
  DecideKeep(VUzzerState &state);

  VUzzerMidCalleeRef operator()(void);

 private:
  VUzzerState &state;
};

struct RunEHB : public hierarflow::HierarFlowRoutine<VUzzerMidInputType,
                                                     VUzzerMidOutputType> {
 public:
  RunEHB(VUzzerState &state);

  VUzzerMidCalleeRef operator()(void);

 private:
  VUzzerState &state;
};

struct ExecutePUT
    : public hierarflow::HierarFlowRoutine<
          VUzzerMidInputType, double(const std::shared_ptr<VUzzerTestcase> &,
                                     feedback::FileFeedback &)> {
 public:
  ExecutePUT(VUzzerState &state);

  VUzzerMidCalleeRef operator()(void);

 private:
  VUzzerState &state;
};

struct ExecuteTaintPUT
    : public hierarflow::HierarFlowRoutine<
          VUzzerMidInputType, double(const std::shared_ptr<VUzzerTestcase> &,
                                     feedback::FileFeedback &)> {
 public:
  ExecuteTaintPUT(VUzzerState &state);

  VUzzerMidCalleeRef operator()(void);

 private:
  VUzzerState &state;
};

}  // namespace fuzzuf::algorithm::vuzzer::routine::other
