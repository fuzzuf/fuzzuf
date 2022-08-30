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
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_mutation_hierarflow_routines.hpp"

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_testcase.hpp"

namespace fuzzuf::algorithm::afl::routine::mutation {

using AFLplusplusTestcase = aflplusplus::AFLplusplusTestcase;

// explicit specialization
template <>
AFLMutCalleeRef<AFLplusplusState> HavocTemplate<AFLplusplusState>::operator()(
    AFLMutatorTemplate<AFLplusplusState>& mutator) {
  // Declare the alias just to omit "this->" in this function.
  auto& state = this->state;

  s32 stage_max_multiplier;
  if (state.doing_det)
    stage_max_multiplier = option::GetHavocCyclesInit(state);
  else
    stage_max_multiplier = option::GetHavocCycles(state);

  using afl::dictionary::AFLDictData;

  if (this->DoHavoc(mutator, *state.mutop_optimizer,
                    aflplusplus::havoc::AFLplusplusCustomCases, "more_havoc",
                    "more_havoc", state.orig_perf, stage_max_multiplier,
                    option::STAGE_HAVOC)) {
    this->SetResponseValue(true);
    return this->GoToParent();
  }

  return this->GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::afl::routine::mutation
