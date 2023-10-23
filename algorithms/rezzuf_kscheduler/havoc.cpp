/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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

#include "fuzzuf/algorithms/rezzuf_kscheduler/havoc.hpp"

#include <limits>

#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

afl::routine::mutation::AFLMutCalleeRef<State> Havoc::operator()(Havoc::RezzufMutator &mutator) {
  // Declare the alias just to omit "this->" in this function.
  auto &state = this->state;

  s32 stage_max_multiplier = afl::option::GetHavocCycles(state);

  if (this->DoHavoc(
          mutator, *state.havoc_optimizer,
          aflplusplus::havoc::AFLplusplusCustomCases<State>(state),
          "more_havoc", "more_havoc", state.orig_perf, stage_max_multiplier,
          afl::option::STAGE_HAVOC)) {
    this->SetResponseValue(true);
    return this->GoToParent();
  }

  return this->GoToDefaultNext();
}

}

