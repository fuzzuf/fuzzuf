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

#include "fuzzuf/algorithms/rezzuf_kscheduler/abandon_entry.hpp"

#include <limits>

#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

afl::routine::other::AFLMidCalleeRef<State> AbandonEntry::operator()(
    std::shared_ptr<Testcase> testcase) {
  state.splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!state.stop_soon && !testcase->cal_failed && !testcase->WasFuzzed()) {
    state.pending_not_fuzzed--;
    if (testcase->favored) state.pending_favored--;
  }

  testcase->fuzz_level++;

  testcase->input->Unload();

  // ReponseValue should be set in previous steps, so do nothing here
  return this->GoToDefaultNext();
}

}

