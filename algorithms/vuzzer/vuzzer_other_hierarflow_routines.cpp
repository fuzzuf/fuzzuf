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
 * @file VUzzerOtherHierarFlowRoutines.cpp
 * @brief HieraFlow nodes for general purpose methods
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/vuzzer/vuzzer_other_hierarflow_routines.hpp"

#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/get_hash.hpp"

namespace fuzzuf::algorithm::vuzzer::routine::other {

FuzzLoop::FuzzLoop(VUzzerState &state) : state(state) {}

utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
FuzzLoop::operator()(void) {
  CallSuccessors();
  state.loop_cnt++;
  return GoToDefaultNext();
}

DecideKeep::DecideKeep(VUzzerState &state) : state(state) {}

/**
 * @brief Mark some seeds as special and save them to keep_queue.
 */
VUzzerMidCalleeRef DecideKeep::operator()(void) {
  if (state.errorbb) {
    if (state.loop_cnt > state.gennum / 5) {
      state.bbslide = std::max(state.bbslide, state.gennum / 20);
      state.keepslide = std::max(state.keepslide, state.gennum / 100);
      state.keepfilenum = state.keepfilenum / 2;
    }
    if (0 < state.loop_cnt && state.loop_cnt < state.gennum / 5 &&
        state.loop_cnt % state.keepslide == 0) {
      std::sample(state.seed_queue.begin(), state.seed_queue.end(),
                  std::back_inserter(state.keep_queue), state.keepfilenum,
                  std::mt19937{std::random_device{}()});
      DEBUG("Keep queue");
      for (const auto &seed : state.keep_queue)
        DEBUG("%s", seed->input->GetPath().c_str());
    }
  }
  CallSuccessors();
  return GoToDefaultNext();
}

RunEHB::RunEHB(VUzzerState &state) : state(state) {}

/**
 *
 * @brief Detect EHBs based on bb traces taken during executions
 */
VUzzerMidCalleeRef RunEHB::operator()(void) {
  feedback::ExitStatusFeedback exit_status;
  std::vector<u64> all_bb;
  std::vector<boost::dynamic_bitset<>> bb_sets;
  if (state.loop_cnt > 40 && state.loop_cnt % state.bbslide == 0) {
    DEBUG("Starting EHB calculation\n");
    /** Collect all bb covs by executing seeds from seed_queue.
     * seed1 {0x4000100 : 10, 0x4000f00 : 1 ... }
     * seed2 {0x4000100 : 1, 0x4000200 : 4 ... }
     * seed1  01000001....
     * seed2  01100000....
     */
    for (const auto &testcase : state.seed_queue) {
      testcase->input->Load();
      auto inp_feed = state.RunExecutor(testcase->input->GetBuf(),
                                        testcase->input->GetLen(), exit_status);
      std::map<u64, u32> bb_cov;
      boost::dynamic_bitset<> bb_set;
      vuzzer::util::ParseBBCov(inp_feed, bb_cov);
      vuzzer::util::DictToBitsWithKeys(bb_cov, all_bb, bb_set);
      bb_sets.emplace_back(bb_set);
      testcase->input->Unload();
    }

    /* Count frequencies of every bbs */
    const u32 ratio =
        (state.setting->ehb_bb_ratio / 100) * state.setting->pop_size;
    for (size_t i = 0; i < all_bb.size(); i++) {
      size_t check_idx = all_bb.size() - 1 - i;
      u32 bb_appear = 0;
      for (auto &bb_set : bb_sets) {
        if (bb_set.size() <= check_idx) continue;
        bb_appear += bb_set[check_idx];
      }
      if (bb_appear > ratio &&
          state.good_bbs.find(all_bb[i]) != state.good_bbs.end()) {
        state.ehb_inc.insert(all_bb[i]);
      }
      /* TODO: Dump all EHB addrs to file */
    }
  }
  CallSuccessors();
  return GoToDefaultNext();
}

ExecutePUT::ExecutePUT(VUzzerState &state) : state(state) {}

/**
 * @brief Execute PUT
 */
VUzzerMidCalleeRef ExecutePUT::operator()(void) {
  DEBUG("ExecutePUT pending(%zu)\n", state.pending_queue.size());
  feedback::ExitStatusFeedback exit_status;
  /* Execute all inputs from pending_queue */
  for (const auto &testcase : state.pending_queue) {
    testcase->input->Load();

    auto inp_feed = state.RunExecutor(testcase->input->GetBuf(),
                                      testcase->input->GetLen(), exit_status);

    /* Calculate fitness score in child node (i.e. UpdateFitness method) */
    auto score = CallSuccessors(testcase, inp_feed);
    testcase->fitness = score;
    DEBUG("Score %s : %lf", testcase->input->GetPath().c_str(), score);

    /* If we encount crash, then triage it. */
    /* TODO: Consider other reasons? */
    if (exit_status.exit_reason == feedback::PUTExitReasonType::FAULT_CRASH) {
      std::string crash_hash = fuzzuf::utils::GetSHA1HashFromFile(
          testcase->input->GetPath().native(), testcase->input->GetLen());
      DEBUG("Testcase %s crashed! (%s)\n", testcase->input->GetPath().c_str(),
            crash_hash.c_str());
      if (state.crash_hashes.find(crash_hash) == state.crash_hashes.end()) {
        /* VUzzer has found a new crash input:) */
        state.crash_hashes.insert(crash_hash);
        /* TODO: File path format */
        std::string crash_path = fuzzuf::utils::StrPrintf(
            "%s/crashes/id:%06llu", state.setting->out_dir.c_str(),
            state.unique_crashes);

        int fd = fuzzuf::utils::OpenFile(crash_path,
                                         O_WRONLY | O_CREAT | O_EXCL, 0600);
        fuzzuf::utils::WriteFile(fd, testcase->input->GetBuf(),
                                 testcase->input->GetLen());
        fuzzuf::utils::CloseFile(fd);
        state.unique_crashes++;
      }
      /* TODO: Implement STOPONCRASH mode */
    }
    testcase->input->Unload();
    /* Move a seed to seed_queue from pending_queue. */
    state.seed_queue.emplace_back(testcase);
  }
  state.pending_queue.clear();
  return GoToDefaultNext();
}

ExecuteTaintPUT::ExecuteTaintPUT(VUzzerState &state) : state(state) {}

/**
 * @brief Execute PUT by taint engine
 */
VUzzerMidCalleeRef ExecuteTaintPUT::operator()(void) {
  DEBUG("ExecuteTaint taint_queue(%zu)\n", state.taint_queue.size());
  if (state.taint_queue.empty()) return GoToDefaultNext();

  /* Execute PUT with seeds taken from taint_queue */
  feedback::ExitStatusFeedback exit_status;
  for (const auto &testcase : state.taint_queue) {
    u64 id = testcase->input->GetID();
    /* If we have already executed the seed then continue.
     * FIXME: Occasionally taint executor doesn't record any taint info. Both
     * taint_cmp_offsets and taint_lea_offsets could become empty.
     */
    if (state.taint_cmp_offsets.find(id) != state.taint_cmp_offsets.end() ||
        state.taint_lea_offsets.find(id) != state.taint_lea_offsets.end())
      continue;
    testcase->input->Load();
    auto inp_feed = state.RunTaintExecutor(
        testcase->input->GetBuf(), testcase->input->GetLen(), exit_status);

    CallSuccessors(testcase, inp_feed);

    testcase->input->Unload();
  }
  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::vuzzer::routine::other
