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

#include "fuzzuf/algorithms/rezzuf_kscheduler/load_seed_if_needed.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/option.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

// Seed should be loaded on memory when calibration or trimming is needed
afl::routine::other::AFLMidCalleeRef<State> LoadSeedIfNeeded::operator()(
    std::shared_ptr<Testcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  
  using Tag = typename State::Tag;
  if constexpr ( afl::option::EnableKScheduler<Tag>() ) {
    // Early reject a seed if didn't hit any top border edge
    const double thres_energy = state.CheckTopBorderEdge( *testcase );
    if (std::fpclassify(thres_energy) == FP_ZERO){
      if (!testcase->was_fuzzed) 
        testcase->was_fuzzed = true;
      this->SetResponseValue(true);
      return this->GoToParent();
    }
    // Early reject a seed whose execution trace(i.e., bitmap) is duplicated with other seeds.
    if (testcase->cnt_free_cksum_dup == 1){
      if (!testcase->was_fuzzed)
        testcase->was_fuzzed = true;
      fprintf(state.sched_log_file, " duplicated \n");
      this->SetResponseValue(true);
      return this->GoToParent();
    }
    if (testcase->cnt_free_cksum == state.last_cnt_free_cksum){
      if (!testcase->was_fuzzed) {
        testcase->was_fuzzed = true;
      }
      fprintf(state.sched_log_file, " duplicated \n");
      this->SetResponseValue(true);
      return this->GoToParent();
    }
 
    state.last_cnt_free_cksum  = testcase->cnt_free_cksum;
  }

  if (testcase->cal_failed > 0 || !testcase->trim_done) {
    testcase->input->Load();
  }

  return this->GoToDefaultNext();
}

}

