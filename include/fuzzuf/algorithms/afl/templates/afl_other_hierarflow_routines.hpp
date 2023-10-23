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

#include "fuzzuf/algorithms/afl/afl_macro.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/kscheduler/dump_coverage.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"

// routines other than mutations and updates
namespace fuzzuf::algorithm::afl::routine::other {

template <class State>
CullQueueTemplate<State>::CullQueueTemplate(State &state) : state(state) {}

template <class State>
utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
CullQueueTemplate<State>::operator()(void) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  using Tag = typename State::Tag;
  if constexpr ( !option::EnableKScheduler< Tag >() ) {
    if (state.setting->dumb_mode || !state.score_changed) {
      return this->GoToDefaultNext();
    }
  }

  state.score_changed = false;

  if constexpr ( option::EnableKScheduler<Tag>() ) {
    if( !state.math_cache_computed_before ){
       state.ComputeMathCache();
       state.last_math_cache_time = fuzzuf::utils::GetCurTimeMs() / 1000;
       state.math_cache_computed_before = 1;
    }
    // recompute the math cache every 2 minutes
    else if( fuzzuf::utils::GetCurTimeMs()/1000 - state.last_math_cache_time > 120 ) {
      state.ComputeMathCache();
      state.last_math_cache_time = fuzzuf::utils::GetCurTimeMs()/1000;
    }
    // clear ptr_energy array
    std::fill( state.ptr_energy.begin(), state.ptr_energy.end(), typename State::my_union{ 0, nullptr } );
    std::fill( state.energy_arr.begin(), state.energy_arr.end(), 0.0 );
  }
  // arrary cnt
  int arr_cnt = 0;

  std::bitset<option::GetMapSize<Tag>()> has_top_rated;

  state.queued_favored = 0;
  state.pending_favored = 0;
  
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    // check if there is a not_fuzzed seed
    bool found_not_fuzzed_seed = false;
    bool found_not_fuzzed2_seed = false;
    for (const auto &testcase : state.case_queue) {
      // check if there is a not fuzzed seed, determine go greedy or weighted random selection 
      if(!testcase->was_fuzzed) {
        found_not_fuzzed_seed = true;
      }
      if(!testcase->was_fuzzed2) {
        found_not_fuzzed2_seed = true;
      }
      if(!testcase->cnt_free_cksum_dup) {
        double energy = state.CheckBorderEdge(*testcase);
        state.ptr_energy[arr_cnt].energy = energy;
        state.ptr_energy[arr_cnt].seed = testcase;
        arr_cnt += 1;
      }
    }
    // sort ptr_energy using energy in decreasing order
    if constexpr ( option::EnableKSchedulerSortByEnergy<Tag>() ) {
      std::sort(
        state.ptr_energy.begin(),
        std::next( state.ptr_energy.begin(), arr_cnt ),
        []( const auto &l, const auto &r ) -> bool {
          return l.energy > r.energy;
        }
      );
    }
    //auto& queue_cur = state.case_queue[state.current_entry];
    if(found_not_fuzzed_seed){
      // greedly select the not_fuzzed seed with largest energy
      for (int idx=0; idx<arr_cnt; idx++){
        if (!((state.ptr_energy[idx].seed)->was_fuzzed)){
	  const auto index = std::distance( state.case_queue.begin(), std::find( state.case_queue.begin(), state.case_queue.end(), state.ptr_energy[idx].seed ) );
          state.current_entry = index;
          //queue_cur = state.ptr_energy[idx].seed;
          break; 
        }
      }
    }
    else{
      // if all seeds are fuzzed (selected with equal times), then reset was_fuzzed for all seeds.
      if (!found_not_fuzzed2_seed){
        for (auto &testcase : state.case_queue) {
          testcase->was_fuzzed2 = false;
	}
        state.current_entry = 0;
      }
      // greedly select the not_fuzzed seed with largest energy
      for (int idx=0; idx<arr_cnt; idx++){
        if (!((state.ptr_energy[idx].seed)->was_fuzzed2)){
	  const auto index = std::distance( state.case_queue.begin(), std::find( state.case_queue.begin(), state.case_queue.end(), state.ptr_energy[idx].seed ) );
          state.current_entry = index;
          (state.ptr_energy[idx].seed)->was_fuzzed2 = true;
          break;
        }
      }
    }
    if (fuzzuf::utils::GetCurTimeMs()/1000 - state.last_edge_log_time > 300){
      // read signal, if "0" return, if "1" reload centrality file 
      if( fs::exists( "signal" ) ) {
        std::fstream fp( "signal", std::ios::out );
        if( !fp.good() ){
          std::perror("signal open failed \n");
          std::exit(0);
        }
        fp << "1\n";
      }
      state.ReloadCentralityFile();
      utils::kscheduler::DumpCoverage( "cur_coverage", state.virgin_bits );
      fprintf(state.edge_log_file, "edge cov %d ", int(fuzzuf::utils::CountNon255Bytes(&state.virgin_bits[0], state.virgin_bits.size() )));
      std::time_t now;
      struct tm *tm;
      now = time(0);
      if((tm = localtime (&now)) == NULL) {
        printf("Error extracting time stuff\n");
      }
      else{
        fprintf(state.edge_log_file, "%04d-%02d-%02d %02d:%02d:%02d\n",
          tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
          tm->tm_hour, tm->tm_min, tm->tm_sec);
      } 
      fflush(state.edge_log_file);
      state.last_edge_log_time = fuzzuf::utils::GetCurTimeMs()/1000;
    }
  }
  else {
    for (const auto &testcase : state.case_queue) {
      testcase->favored = false;
    }
  }
  
  for (u32 i = 0; i < option::GetMapSize<Tag>(); i++) {
    if (state.top_rated[i] && !has_top_rated[i]) {
      auto &top_testcase = state.top_rated[i].value().get();

      has_top_rated |= *(top_testcase.trace_mini);

      top_testcase.favored = true;
      state.queued_favored++;

      if (!top_testcase.WasFuzzed()) state.pending_favored++;
    }
  }

  for (const auto &testcase : state.case_queue) {
    state.MarkAsRedundant(*testcase, !testcase->favored);
  }
  
  if constexpr ( option::EnableKScheduler< Tag >() ) {
    // get the testcase indexed by state.current_entry and start mutations
    auto &testcase = state.case_queue[state.current_entry];
    this->CallSuccessors(testcase);
    state.current_entry++;
  }
  
  return this->GoToDefaultNext();
}

template <class State>
SelectSeedTemplate<State>::SelectSeedTemplate(State &state) : state(state) {}

template <class State>
utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
SelectSeedTemplate<State>::operator()(void) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  if (state.queue_cycle == 0 ||
      state.current_entry >= state.case_queue.size()) {
    state.queue_cycle++;
    state.current_entry = state.seek_to;  // seek_to is used in resume mode
    state.seek_to = 0;
    state.cur_skipped_paths = 0;

    state.ShowStats();
    if (state.not_on_tty) {
      ACTF("Entering queue cycle %llu.", state.queue_cycle);
      fflush(stdout);
    }

    /* If we had a full queue cycle with no new finds, try
       recombination strategies next. */

    if (state.queued_paths == prev_queued) {
      if (state.use_splicing)
        state.cycles_wo_finds++;
      else
        state.use_splicing = true;
    } else
      state.cycles_wo_finds = 0;

    prev_queued = state.queued_paths;

#if 0
        if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
            sync_fuzzers(use_argv);
#endif

    DEBUG_ASSERT(state.current_entry < state.case_queue.size());
  }

  using Tag = typename State::Tag;
  if constexpr ( !option::EnableKScheduler< Tag >() ) {
    // get the testcase indexed by state.current_entry and start mutations
    auto &testcase = state.case_queue[state.current_entry];
    this->CallSuccessors(testcase);
    state.current_entry++;
  }

#if 0
    auto skipped_fuzz = CallSuccessors(testcase);

    if (!state.stop_soon && state.sync_id && !skipped_fuzz) {
      if (!(state.sync_interval_cnt++ % option::GetSyncInterval(state)))
        SyncFuzzers(use_argv);
    }
#endif

  return this->GoToDefaultNext();
}

template <class State>
ConsiderSkipMutTemplate<State>::ConsiderSkipMutTemplate(State &state)
    : state(state) {}

// Randomly, sometimes skip the entire process of mutations
template <class State>
AFLMidCalleeRef<State> ConsiderSkipMutTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE

  using Tag = typename State::Tag;
  if constexpr ( option::EnableKScheduler<Tag>() ) {
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
  else {
    // just an alias of afl::util::UR
    auto UR = [this](u32 limit) { return afl::util::UR(limit, state.rand_fd); };
    if (state.setting->ignore_finds) {
      if (testcase->depth > 1) {
        this->SetResponseValue(true);
        return this->GoToParent();
      }
    } else {
      if (state.pending_favored) {
        if ((testcase->WasFuzzed() || !testcase->favored) &&
            UR(100) < option::GetSkipToNewProb(state)) {
          this->SetResponseValue(true);
          return this->GoToParent();
        }
      } else if (!state.setting->dumb_mode && !testcase->favored &&
                 state.queued_paths > 10) {
        if (state.queue_cycle > 1 && !testcase->WasFuzzed()) {
          if (UR(100) < option::GetSkipNfavNewProb(state)) {
            this->SetResponseValue(true);
            return this->GoToParent();
          }
        } else {
          if (UR(100) < option::GetSkipNfavOldProb(state)) {
            this->SetResponseValue(true);
            return this->GoToParent();
          }
        }
      }
    }
  }

  if (state.not_on_tty) {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         state.current_entry, state.queued_paths, state.unique_crashes);
    fflush(stdout);
  }

  // We don't use LoadByMmap here because we may modify
  // the underlying file in calibration and trimming.
  // The original AFL also should not do that though it does.
  testcase->input->Load();

  return this->GoToDefaultNext();
}

template <class State>
RetryCalibrateTemplate<State>::RetryCalibrateTemplate(
    State &state, AFLMidCalleeRef<State> abandon_entry)
    : state(state), abandon_entry(abandon_entry) {}

template <class State>
AFLMidCalleeRef<State> RetryCalibrateTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  auto &input = *testcase->input;

  // Mutator should be allocated after trimming is done
  // auto mutator = Mutator( input );

  state.subseq_tmouts = 0;
  state.cur_depth = testcase->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (testcase->cal_failed == 0) return this->GoToDefaultNext();

  feedback::PUTExitReasonType res = feedback::PUTExitReasonType::FAULT_TMOUT;
  if (testcase->cal_failed < option::GetCalChances(state)) {
    /* Reset exec_cksum to tell calibrate_case to re-execute the testcase
       avoiding the usage of an invalid trace_bits.
       For more info: https://github.com/AFLplusplus/AFLplusplus/pull/425 */

    testcase->exec_cksum = 0;

    // There should be no active instance of InplaceMemoryFeedback at this
    // point. So we can just create a temporary instance to get a result.
    feedback::InplaceMemoryFeedback inp_feed;
    feedback::ExitStatusFeedback exit_status;
    res = state.CalibrateCaseWithFeedDestroyed(
        *testcase, input.GetBuf(), input.GetLen(), inp_feed, exit_status,
        state.queue_cycle - 1, false,true);
    if (res == feedback::PUTExitReasonType::FAULT_ERROR)
      ERROR("Unable to execute target application");
  }

  // FIXME: state.setting->crash_mode?
  if (state.stop_soon || res != state.crash_mode) {
    state.cur_skipped_paths++;
    this->SetResponseValue(true);
    return abandon_entry;
  }

  return this->GoToDefaultNext();
}

template <class State>
TrimCaseTemplate<State>::TrimCaseTemplate(State &state,
                                          AFLMidCalleeRef<State> abandon_entry)
    : state(state), abandon_entry(abandon_entry) {}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

template <class State>
static feedback::PUTExitReasonType DoTrimCase(
    State &state, typename State::OwnTestcase &testcase) {
  auto &input = *testcase.input;

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (input.GetLen() < 5) return feedback::PUTExitReasonType::FAULT_NONE;

  state.bytes_trim_in += input.GetLen();

  /* Select initial chunk len, starting with large steps. */
  u32 len_p2 = fuzzuf::utils::NextP2(input.GetLen());

  u32 remove_len = std::max(len_p2 / option::GetTrimStartSteps(state),
                            option::GetTrimMinBytes(state));

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  // end_len is re-calculated everytime len_p2 is changed
  u32 end_len = std::max(len_p2 / option::GetTrimEndSteps(state),
                         option::GetTrimMinBytes(state));

  feedback::PersistentMemoryFeedback pers_feed;
  u32 trim_exec = 0;
  bool needs_write = false;
  feedback::PUTExitReasonType fault = feedback::PUTExitReasonType::FAULT_NONE;
  while (remove_len >= end_len) {
    u32 remove_pos = remove_len;

    state.stage_name = fuzzuf::utils::StrPrintf(
        "trim %s/%s", afl::util::DescribeInteger(remove_len).c_str(),
        afl::util::DescribeInteger(remove_len).c_str());

    state.stage_cur = 0;
    state.stage_max = input.GetLen() / remove_len;

    while (remove_pos < input.GetLen()) {
      u32 trim_avail = std::min(remove_len, input.GetLen() - remove_pos);

      // FIXME: we can't represent this in fuzzuf without preparing another buf
      // write_with_gap(in_buf, q->len, remove_pos, trim_avail);

      u32 test_len = input.GetLen() - trim_avail;
      std::unique_ptr<u8[]> test_buf(new u8[test_len]);
      u32 move_tail = input.GetLen() - remove_pos - trim_avail;

      std::memcpy(test_buf.get(), input.GetBuf(), remove_pos);
      std::memmove(test_buf.get() + remove_pos,
                   input.GetBuf() + remove_pos + trim_avail, move_tail);

      feedback::ExitStatusFeedback exit_status;

      feedback::InplaceMemoryFeedback inp_feed =
          state.RunExecutorWithClassifyCounts(test_buf.get(), test_len,
                                              exit_status);
      fault = exit_status.exit_reason;
      state.trim_execs++;

      if (state.stop_soon || fault == feedback::PUTExitReasonType::FAULT_ERROR)
        goto abort_trimming;  // FIXME: goto

      /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

      u32 cksum = inp_feed.CalcCksum32();

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == testcase.exec_cksum) {
        input.OverwriteKeepingLoaded(std::move(test_buf), test_len);

        len_p2 = fuzzuf::utils::NextP2(input.GetLen());
        end_len = std::max(len_p2 / option::GetTrimEndSteps(state),
                           option::GetTrimMinBytes(state));

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */

        if (!needs_write) {
          needs_write = true;
          pers_feed = inp_feed.ConvertToPersistent();
        }
      } else {
        remove_pos += remove_len;
      }

      /* Since this can be slow, update the screen every now and then. */

      if (trim_exec % state.stats_update_freq == 0) state.ShowStats();
      trim_exec++;
      state.stage_cur++;
    }

    remove_len >>= 1;
  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {
    // already saved on disk by "input.OverwriteKeepingLoaded()"

    using Tag = typename State::Tag;
    if constexpr ( !option::EnableKScheduler<Tag>() ) {
      state.UpdateBitmapScoreWithRawTrace(
        testcase, pers_feed.mem.get(),
        option::GetMapSize<typename State::Tag>());
    }
  }

abort_trimming:
  state.bytes_trim_out += input.GetLen();
  return fault;
}

template <class State>
AFLMidCalleeRef<State> TrimCaseTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  using Tag = typename State::Tag;
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    testcase->init_perf_score = 100;
    if (testcase->exec_us * 0.05 > state.avg_us_fast) testcase->init_perf_score = 0;
    else if (testcase->exec_us * 0.075 > state.avg_us_fast) testcase->init_perf_score = 1;
    else if (testcase->exec_us * 0.1 > state.avg_us_fast) testcase->init_perf_score = 10;
    else if (testcase->exec_us * 0.25 > state.avg_us_fast) testcase->init_perf_score = 25;
    else if (testcase->exec_us * 0.5 > state.avg_us_fast) testcase->init_perf_score = 50;
    else if (testcase->exec_us * 0.75 > state.avg_us_fast) testcase->init_perf_score = 75;
    else if (testcase->exec_us * 4 < state.avg_us_fast) testcase->init_perf_score = 300;
    else if (testcase->exec_us * 3 < state.avg_us_fast) testcase->init_perf_score = 200;
    else if (testcase->exec_us * 2 < state.avg_us_fast) testcase->init_perf_score = 150;
    state.init_perf_score = testcase->init_perf_score;

    if(testcase->init_perf_score <= 75) testcase->trim_done = true;
  
    if(testcase->init_perf_score == 0) {
      this->SetResponseValue(true);
      return abandon_entry;
    }
  }

  /************
   * TRIMMING *
   ************/
  if (state.setting->dumb_mode || testcase->trim_done)
    return this->GoToDefaultNext();

  feedback::PUTExitReasonType res = DoTrimCase(state, *testcase);
  if (res == feedback::PUTExitReasonType::FAULT_ERROR)
    ERROR("Unable to execute target application");

  if (state.stop_soon) {
    state.cur_skipped_paths++;
    this->SetResponseValue(true);
    return abandon_entry;
  }

  testcase->trim_done = true;
  return this->GoToDefaultNext();
}

template <class State>
CalcScoreTemplate<State>::CalcScoreTemplate(
    State &state, AFLMidCalleeRef<State> abandon_entry) : state(state), abandon_entry(abandon_entry) {}

template <class State>
AFLMidCalleeRef<State> CalcScoreTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  /*********************
   * PERFORMANCE SCORE *
   *********************/
  
  state.orig_perf = state.DoCalcScore(*testcase);
  using Tag = typename State::Tag;
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    if (std::fpclassify(state.orig_perf) == FP_ZERO) {
      this->SetResponseValue(true);
      return abandon_entry;
    }
  }
  return this->GoToDefaultNext();
}

template <class State>
ApplyDetMutsTemplate<State>::ApplyDetMutsTemplate(
    State &state, AFLMidCalleeRef<State> abandon_entry)
    : state(state), abandon_entry(abandon_entry) {}

template <class State>
AFLMidCalleeRef<State> ApplyDetMutsTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  // We no longer modify this testcase.
  // So we can reload the file with mmap.
  testcase->input->LoadByMmap();  // no need to Unload

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (fuzz_level > 0), or if it has gone through
     deterministic testing in earlier, resumed runs (passed_det). */

  if (state.skip_deterministic || testcase->WasFuzzed() ||
      testcase->passed_det) {
    state.doing_det = false;
    return this->GoToDefaultNext();
  }
  using Tag = typename State::Tag;
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    if( testcase->init_perf_score <= 25 ) {
      state.doing_det = false;
      return this->GoToDefaultNext();
    }
  }

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (state.master_max &&
      (testcase->exec_cksum % state.master_max) != state.master_id - 1) {
    state.doing_det = false;
    return this->GoToDefaultNext();
  }

  state.doing_det = true;

  auto mutator = AFLMutatorTemplate<State>(*testcase->input, state);

  state.stage_val_type = option::STAGE_VAL_NONE;

  // this will be required in dictionary construction and eff_map construction
  state.queue_cur_exec_cksum = testcase->exec_cksum;

  // call deterministic mutations
  // if they return true, then we should go to abandon_entry
  auto should_abandon_entry = this->CallSuccessors(mutator);

  if (should_abandon_entry) {
    this->SetResponseValue(true);
    return abandon_entry;
  }

  // NOTE: "if (!testcase->passed_det)" seems unnecessary to me
  // because passed_det == 0 always holds here
  if (!testcase->passed_det) state.MarkAsDetDone(*testcase);

  return this->GoToDefaultNext();
}

template <class State>
ApplyRandMutsTemplate<State>::ApplyRandMutsTemplate(
    State &state, AFLMidCalleeRef<State> abandon_entry)
    : state(state), abandon_entry(abandon_entry) {}

template <class State>
AFLMidCalleeRef<State> ApplyRandMutsTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  auto mutator = AFLMutatorTemplate<State>(*testcase->input, state);

  // call probablistic mutations
  // if they return true, then we should go to abandon_entry
  auto should_abandon_entry = this->CallSuccessors(mutator);
  if (should_abandon_entry) {
    this->SetResponseValue(true);
    return abandon_entry;
  }

  return this->GoToDefaultNext();
}

template <class State>
AbandonEntryTemplate<State>::AbandonEntryTemplate(State &state)
    : state(state) {}

template <class State>
AFLMidCalleeRef<State> AbandonEntryTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  state.splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!state.stop_soon && !testcase->cal_failed && !testcase->WasFuzzed()) {
    // Unlike AFLFast, we don't increment fuzz_level endlessly.
    testcase->MarkFuzzed();
    state.pending_not_fuzzed--;
    if (testcase->favored) state.pending_favored--;
  }

  testcase->input->Unload();

  // ReponseValue should be set in previous steps, so do nothing here
  return this->GoToDefaultNext();
}

template <class State>
ExecutePUTTemplate<State>::ExecutePUTTemplate(State &state, bool fail_on_too_slow) : state(state), fail_on_too_slow( fail_on_too_slow ) {}

template <class State>
utils::NullableRef<hierarflow::HierarFlowCallee<bool(const u8 *, u32)>>
ExecutePUTTemplate<State>::operator()(const u8 *input, u32 len) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  feedback::ExitStatusFeedback exit_status;

  using Tag = typename State::Tag;
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    if( fail_on_too_slow ) {
      const u64 start_us = fuzzuf::utils::GetCurTimeUs();
      auto inp_feed = state.RunExecutorWithClassifyCounts(input, len, exit_status);
      const u64 end_us = fuzzuf::utils::GetCurTimeUs();
      double exec_num = ((double)1000000.0)/(end_us-start_us);
      if (exec_num <= 10) {  
        this->SetResponseValue(true);
        return this->GoToParent();
      }
      bool should_abort = CallSuccessors(input, len, inp_feed, exit_status);
      SetResponseValue(should_abort);
    }
    else {
      auto inp_feed = state.RunExecutorWithClassifyCounts(input, len, exit_status);
      bool should_abort = CallSuccessors(input, len, inp_feed, exit_status);
      SetResponseValue(should_abort);
    }
  }
  else {
    auto inp_feed = state.RunExecutorWithClassifyCounts(input, len, exit_status);
    bool should_abort = CallSuccessors(input, len, inp_feed, exit_status);
    SetResponseValue(should_abort);
  }
  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::afl::routine::other
