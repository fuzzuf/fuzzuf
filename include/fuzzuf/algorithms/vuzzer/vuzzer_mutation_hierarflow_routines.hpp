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

namespace fuzzuf::algorithm::vuzzer::routine::mutation {

using VUzzerMutInputType = void(void);
using VUzzerMutCalleeRef =
    utils::NullableRef<hierarflow::HierarFlowCallee<VUzzerMutInputType>>;
using VUzzerMutOutputType = void(void);

struct Mutate : public hierarflow::HierarFlowRoutine<VUzzerMutInputType,
                                                     VUzzerMutOutputType> {
 public:
  Mutate(VUzzerState &state);

  VUzzerMutCalleeRef operator()(void);

 private:
  VUzzerState &state;
};

}  // namespace fuzzuf::algorithm::vuzzer::routine::mutation
