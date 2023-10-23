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

#include "fuzzuf/algorithms/rezzuf_kscheduler/apply_rand_muts.hpp"

#include <limits>

#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {


afl::routine::other::AFLMidCalleeRef<State> ApplyRandMuts::operator()(
    std::shared_ptr<Testcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  // We no longer modify this testcase.
  // So we can reload the file with mmap.
  testcase->input->LoadByMmap();  // no need to Unload

  using RezzufMutator = afl::AFLMutatorTemplate<State>;

  auto mutator = RezzufMutator(*testcase->input, state);

  // call probablistic mutations
  // if they return true, then we should go to abandon_entry
  auto should_abandon_entry = this->CallSuccessors(mutator);
  if (should_abandon_entry) {
    this->SetResponseValue(true);
    return abandon_entry;
  }

  return this->GoToDefaultNext();
}

}

