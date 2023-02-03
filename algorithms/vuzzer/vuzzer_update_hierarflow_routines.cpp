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
/**
 * @file VUzzerUpdateHierarFlowRoutines.cpp
 * @brief HieraFlow nodes for update methods
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/vuzzer/vuzzer_update_hierarflow_routines.hpp"

#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::vuzzer::routine::update {

UpdateFitness::UpdateFitness(VUzzerState &state) : state(state) {}

/**
 * @brief Calculate fitness score of seed based on feedback
 * @param (testcase) Seed
 * @param (inp_feed) Feedback
 * @return Fitness score
 */
VUzzerUpdCalleeRef UpdateFitness::operator()(
    const std::shared_ptr<VUzzerTestcase> &testcase,
    feedback::FileFeedback &inp_feed) {
  DEBUG("UpdateFitness");
  std::map<u64, u32> bb_cov;
  std::set<u64> bb_without_ehb;
  std::vector<u64> diff;
  std::set<u64> ehb_all;

  int ehb_cnt = 0;
  double score = 0.0, ehb_score = 0.0;
  u32 input_len = testcase->input->GetLen();

  ehb_all = state.ehb;
  ehb_all.merge(state.ehb_inc);

  /* Parse a BB cov file taken during the execution */
  vuzzer::util::ParseBBCov(inp_feed, bb_cov);

  /* Collect BBs except EHB from bb_cov */
  for (const auto &bb : bb_cov) {
    if (ehb_all.find(bb.first) == ehb_all.end()) {
      bb_without_ehb.insert(bb.first);
    } else {
      ehb_cnt++;  // Count EHBs from BB coverage
    }
  }

  /* The more EHBs PUT records the less score become. */
  if (ehb_cnt)
    ehb_score =
        -1 * (bb_cov.size() * state.setting->ehb_fitness_ratio / ehb_cnt);
  DEBUG("EHB score %lf (%zu) * %lf / %d", ehb_score, bb_cov.size(),
        state.setting->ehb_fitness_ratio, ehb_cnt);

  /* Check wheter vuzzer has found a new BB coverage by comparing to previous
   * BBs (state.seen_bbs) */
  std::set_difference(bb_without_ehb.begin(), bb_without_ehb.end(),
                      state.seen_bbs.begin(), state.seen_bbs.end(),
                      back_inserter(diff));
  if (diff.size()) {
    /* New BB coverage! */
    DEBUG("New coverage");
    for (const auto &bb : diff) DEBUG("0x%llx", bb);

    state.has_new_cov = true;  // XXX: Duplicate unncessary variable has_new_cov

    /* Add new seed to taint_queue. It'll be executed by taint executor. */
    state.taint_queue.emplace_back(testcase);

    /* Update seen_bbs */
    for (const auto &bb : diff) state.seen_bbs.insert(bb);

    /* Remove all seeds whose coverage is subset of the new seed */
    CallSuccessors(testcase, bb_cov);
  }

  /* Calculate fitness score from BB cov */
  for (const auto &bb : bb_cov) {
    u64 addr = bb.first;
    u32 cnt = bb.second;

    if (cnt > state.setting->bb_cnt_max) cnt = state.setting->bb_cnt_max;

    int cnt_log = int(std::log2(cnt + 1));

    if (ehb_all.find(addr) != ehb_all.end()) {
      /* EHB */
      score = score + (cnt_log * ehb_score);
    } else if (state.bb_weights.find(addr) != state.bb_weights.end()) {
      /* BB which has already been found by static analysis tool (BB-weight.py)
       */
      score = score + (cnt_log * state.bb_weights[addr]);
    } else {
      /* Otherwise */
      score = score + cnt_log;
    }
  }

  if (input_len > state.setting->input_len_max)
    SetResponseValue((score * bb_without_ehb.size()) /
                     int(std::log2(input_len + 1)));
  else
    SetResponseValue(score * bb_without_ehb.size());

  return GoToDefaultNext();
}

UpdateTaint::UpdateTaint(VUzzerState &state) : state(state) {}

/**
 * @brief Get taint information
 * @param (testcase) Seed
 * @param (inp_feed) Feedback
 */
VUzzerUpdCalleeRef UpdateTaint::operator()(
    const std::shared_ptr<VUzzerTestcase> &testcase,
    feedback::FileFeedback &inp_feed) {
  DEBUG("UpdateTaint");
  /* Parse a taint file taken during the execution */
  vuzzer::util::ParseTaintInfo(state, testcase, inp_feed);
  CallSuccessors();
  return GoToDefaultNext();
}

UpdateQueue::UpdateQueue(VUzzerState &state) : state(state) {}

/**
 * @brief Delete seeds from seed_queue whose score is not high
 * @todo Consider time complexity. Currently it calls DeleteFromQueue method at
 * every deletion of seeds. It costs O(n^2).
 */
utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
UpdateQueue::operator()(void) {
  DEBUG("UpdateQueue seed_queue(%zu)\n", state.seed_queue.size());

  /* Sort seed_queue in order by fitness score */
  std::sort(state.seed_queue.begin(), state.seed_queue.end(),
            [](const std::shared_ptr<VUzzerTestcase> &left,
               const std::shared_ptr<VUzzerTestcase> &right) {
              return left->fitness > right->fitness;
            });

  /* Delete seeds whose score is less than best score */
  auto itr = state.seed_queue.begin();
  for (u32 i = 0; itr != state.seed_queue.end(); i++) {
    DEBUG("Seed %s (%lf)", (*itr)->input->GetPath().c_str(), (*itr)->fitness);
    if (i >= state.setting->keep_num_of_seed_queue) {
      state.bb_covs.erase((*itr)->input->GetID());  // Delete BB cov
      itr = state.DeleteFromQueue(state.seed_queue,
                                  itr);  // Erase seed from queue
    } else {
      itr++;
    }
  }
  for (const auto &seed : state.seed_queue)
    DEBUG("Seed %s (%lf)", seed->input->GetPath().c_str(), seed->fitness);

  CallSuccessors();
  return GoToDefaultNext();
}

TrimQueue::TrimQueue(VUzzerState &state) : state(state) {}

/**
 * @brief Prune the seeds(if at all), whose trace is subset of the new seed just
 * got executed.
 * @param (testcase) New seed just got executed
 * @param (bb_cov) BB coverage of new seed
 */
utils::NullableRef<hierarflow::HierarFlowCallee<void(
    const std::shared_ptr<VUzzerTestcase> &testcase, std::map<u64, u32> &)>>
TrimQueue::operator()(const std::shared_ptr<VUzzerTestcase> &testcase,
                      std::map<u64, u32> &bb_cov) {
  DEBUG("TrimeQueue queue size(%zu)", state.seed_queue.size());
  boost::dynamic_bitset<> bb_set;
  /* Convert BB cov to bitset like: {0x4000100 : 10, 0x4000f00 : 1 ... } ->
   * 01000001....*/
  vuzzer::util::DictToBitsWithKeys(bb_cov, state.seen_bbs_table_for_bits,
                                   bb_set);

  /* Find and delete the seeds from seed_queue. */
  auto itr = state.seed_queue.begin();
  while (itr != state.seed_queue.end()) {
    if (state.bb_covs.find((*itr)->input->GetID()) == state.bb_covs.end()) {
      itr++;
      continue;
    }
    boost::dynamic_bitset<> &tmp = state.bb_covs[(*itr)->input->GetID()];

    /* We need make both bitsets same size */
    if (tmp.size() < bb_set.size())
      tmp.resize(bb_set.size());
    else if (tmp.size() > bb_set.size())
      bb_set.resize(tmp.size());

    /* Check wheter trace is subset of the new seed. */
    if (tmp.is_subset_of(bb_set)) {
      /* Delete the seed from seed_queue */
      DEBUG("bb_covs[%s] < bb_covs[%s]", (*itr)->input->GetPath().c_str(),
            testcase->input->GetPath().c_str());
      state.bb_covs.erase((*itr)->input->GetID());
      itr = state.DeleteFromQueue(state.seed_queue, itr);
    } else {
      itr++;
    }
  }
  /* Record BB cov bitset to state.bb_covs */
  state.bb_covs[testcase->input->GetID()] = bb_set;
  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::vuzzer::routine::update
