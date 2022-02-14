/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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

#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"

#include "fuzzuf/algorithms/afl/afl_macro.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/logger/logger.hpp"

// routines other than mutations and updates
namespace fuzzuf::algorithm::afl::routine::other {

template<class State>
CullQueueTemplate<State>::CullQueueTemplate(State &state)
    : state(state) {}

template<class State>
NullableRef<HierarFlowCallee<void(void)>> CullQueueTemplate<State>::operator()(void) {
    if (state.setting->dumb_mode || !state.score_changed) return GoToDefaultNext();

    using Tag = typename State::Tag;

    state.score_changed = false;

    std::bitset<option::GetMapSize<Tag>()> has_top_rated;

    state.queued_favored = 0;
    state.pending_favored = 0;

    for (const auto& testcase : state.case_queue) {
        testcase->favored = false;
    }

    for (u32 i=0; i < option::GetMapSize<Tag>(); i++) {
        if (state.top_rated[i] && !has_top_rated[i]) {
            auto &top_testcase = state.top_rated[i].value().get();

            has_top_rated |= *(top_testcase.trace_mini);

            top_testcase.favored = true;
            state.queued_favored++;

            if (!top_testcase.WasFuzzed()) state.pending_favored++;
        }
    }

    for (const auto& testcase : state.case_queue) {
        state.MarkAsRedundant(*testcase, !testcase->favored);
    }

    return GoToDefaultNext();
}

template<class State>
SelectSeedTemplate<State>::SelectSeedTemplate(State &state)
    : state(state) {}

template<class State>
NullableRef<HierarFlowCallee<void(void)>> SelectSeedTemplate<State>::operator()(void) {
    if (state.queue_cycle == 0 || state.current_entry >= state.case_queue.size()) {
        state.queue_cycle++;
        state.current_entry = state.seek_to; // seek_to is used in resume mode
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
            if (state.use_splicing) state.cycles_wo_finds++;
            else state.use_splicing = true;
        } else state.cycles_wo_finds = 0;

        prev_queued = state.queued_paths;

#if 0
        if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
            sync_fuzzers(use_argv);
#endif

        DEBUG_ASSERT(state.current_entry < state.case_queue.size());
    }

    // get the testcase indexed by state.current_entry and start mutations
    auto& testcase = state.case_queue[state.current_entry];
    this->CallSuccessors(testcase);
    state.current_entry++;

#if 0
    auto skipped_fuzz = CallSuccessors(testcase);

    if (!state.stop_soon && state.sync_id && !skipped_fuzz) {
      if (!(state.sync_interval_cnt++ % option::GetSyncInterval(state)))
        SyncFuzzers(use_argv);
    }
#endif

    return this->GoToDefaultNext();
}

template<class State>
ConsiderSkipMutTemplate<State>::ConsiderSkipMutTemplate(State &state)
    : state(state) {}

// Randomly, sometimes skip the entire process of mutations
template<class State>
AFLMidCalleeRef<State> ConsiderSkipMutTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase
) {
    // just an alias of afl::util::UR
    auto UR = [this](u32 limit) {
        return afl::util::UR(limit, state.rand_fd);
    };

    if (state.setting->ignore_finds) {
        if (testcase->depth > 1) {
            this->SetResponseValue(true);
            return this->GoToParent();
        }
    } else {
        if (state.pending_favored) {
            if ( (testcase->WasFuzzed() || !testcase->favored)
              && UR(100) < option::GetSkipToNewProb(state)) {
                this->SetResponseValue(true);
                return this->GoToParent();
            }
        } else if (!state.setting->dumb_mode &&
                   !testcase->favored &&
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

template<class State>
RetryCalibrateTemplate<State>::RetryCalibrateTemplate(
    State &state,
    AFLMidCalleeRef<State> abandon_entry
) : state(state),
    abandon_entry(abandon_entry) {}

template<class State>
AFLMidCalleeRef<State> RetryCalibrateTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase
) {
    auto& input = *testcase->input;

    // Mutator should be allocated after trimming is done
    // auto mutator = Mutator( input );

    state.subseq_tmouts = 0;
    state.cur_depth = testcase->depth;

    /*******************************************
     * CALIBRATION (only if failed earlier on) *
     *******************************************/

    if (testcase->cal_failed == 0) return this->GoToDefaultNext();

    PUTExitReasonType res = PUTExitReasonType::FAULT_TMOUT;
    if (testcase->cal_failed < option::GetCalChances(state)) {
        /* Reset exec_cksum to tell calibrate_case to re-execute the testcase
           avoiding the usage of an invalid trace_bits.
           For more info: https://github.com/AFLplusplus/AFLplusplus/pull/425 */

        testcase->exec_cksum = 0;

        // There should be no active instance of InplaceMemoryFeedback at this point.
        // So we can just create a temporary instance to get a result.
        InplaceMemoryFeedback inp_feed;
        ExitStatusFeedback exit_status;
        res = state.CalibrateCaseWithFeedDestroyed(
            *testcase,
            input.GetBuf(),
            input.GetLen(),
            inp_feed,
            exit_status,
            state.queue_cycle - 1,
            false
        );
        if (res == PUTExitReasonType::FAULT_ERROR)
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

template<class State>
TrimCaseTemplate<State>::TrimCaseTemplate(
    State &state,
    AFLMidCalleeRef<State> abandon_entry
) : state(state),
    abandon_entry(abandon_entry) {}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

template<class State>
static PUTExitReasonType DoTrimCase(
    State &state, typename State::OwnTestcase &testcase
) {
    auto &input = *testcase.input;

    /* Although the trimmer will be less useful when variable behavior is
       detected, it will still work to some extent, so we don't check for
       this. */

    if (input.GetLen() < 5) return PUTExitReasonType::FAULT_NONE;

    state.bytes_trim_in += input.GetLen();

    /* Select initial chunk len, starting with large steps. */
    u32 len_p2 = Util::NextP2(input.GetLen());

    u32 remove_len = std::max(
                        len_p2 / option::GetTrimStartSteps(state),
                        option::GetTrimMinBytes(state)
                     );

    /* Continue until the number of steps gets too high or the stepover
       gets too small. */

    // end_len is re-calculated everytime len_p2 is changed
    u32 end_len = std::max(
                      len_p2 / option::GetTrimEndSteps(state),
                      option::GetTrimMinBytes(state)
                  );

    PersistentMemoryFeedback pers_feed;
    u32 trim_exec = 0;
    bool needs_write = false;
    PUTExitReasonType fault = PUTExitReasonType::FAULT_NONE;
    while (remove_len >= end_len) {
        u32 remove_pos = remove_len;

        state.stage_name = Util::StrPrintf(
                              "trim %s/%s",
                              afl::util::DescribeInteger(remove_len).c_str(),
                              afl::util::DescribeInteger(remove_len).c_str()
                           );

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
            std::memmove(
                test_buf.get() + remove_pos,
                input.GetBuf() + remove_pos + trim_avail,
                move_tail
            );

            ExitStatusFeedback exit_status;

            InplaceMemoryFeedback inp_feed = state.RunExecutorWithClassifyCounts(
                                                 test_buf.get(),
                                                 test_len,
                                                 exit_status
                                             );
            fault = exit_status.exit_reason;
            state.trim_execs++;

            if ( state.stop_soon
              || fault == PUTExitReasonType::FAULT_ERROR)
                goto abort_trimming; //FIXME: goto

            /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

            u32 cksum = inp_feed.CalcCksum32();

            /* If the deletion had no impact on the trace, make it permanent. This
               isn't perfect for variable-path inputs, but we're just making a
               best-effort pass, so it's not a big deal if we end up with false
               negatives every now and then. */

            if (cksum == testcase.exec_cksum) {
                input.OverwriteKeepingLoaded(std::move(test_buf), test_len);

                len_p2 = Util::NextP2(input.GetLen());
                end_len = std::max(
                              len_p2 / option::GetTrimEndSteps(state),
                              option::GetTrimMinBytes(state)
                          );

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

        state.UpdateBitmapScoreWithRawTrace(
            testcase,
            pers_feed.mem.get(),
            option::GetMapSize<typename State::Tag>()
        );
    }

abort_trimming:
    state.bytes_trim_out += input.GetLen();
    return fault;
}

template<class State>
AFLMidCalleeRef<State> TrimCaseTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase
) {
    /************
     * TRIMMING *
     ************/
    if (state.setting->dumb_mode || testcase->trim_done) return this->GoToDefaultNext();


    PUTExitReasonType res = DoTrimCase(state, *testcase);
    if (res == PUTExitReasonType::FAULT_ERROR)
        ERROR("Unable to execute target application");

    if (state.stop_soon) {
        state.cur_skipped_paths++;
        this->SetResponseValue(true);
        return abandon_entry;
    }

    testcase->trim_done = true;
    return this->GoToDefaultNext();
}

template<class State>
CalcScoreTemplate<State>::CalcScoreTemplate(State &state) : state(state) {}

template<class State>
AFLMidCalleeRef<State> CalcScoreTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase
) {
    /*********************
     * PERFORMANCE SCORE *
     *********************/

    state.orig_perf = state.DoCalcScore(*testcase);
    return this->GoToDefaultNext();
}

template<class State>
ApplyDetMutsTemplate<State>::ApplyDetMutsTemplate(
    State &state,
    AFLMidCalleeRef<State> abandon_entry
) : state(state),
    abandon_entry(abandon_entry) {}

template<class State>
AFLMidCalleeRef<State> ApplyDetMutsTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase
) {

    // We no longer modify this testcase.
    // So we can reload the file with mmap.
    testcase->input->LoadByMmap(); // no need to Unload

    /* Skip right away if -d is given, if we have done deterministic fuzzing on
       this entry ourselves (fuzz_level > 0), or if it has gone through deterministic
       testing in earlier, resumed runs (passed_det). */

    if (state.skip_deterministic || testcase->WasFuzzed() || testcase->passed_det) {
        state.doing_det = false;
        return this->GoToDefaultNext();
    }

    /* Skip deterministic fuzzing if exec path checksum puts this out of scope
       for this master instance. */

    if ( state.master_max
      && (testcase->exec_cksum % state.master_max) != state.master_id - 1) {
        state.doing_det = false;
        return this->GoToDefaultNext();
    }

    state.doing_det = true;

    auto mutator = AFLMutatorTemplate<State>( *testcase->input, state );

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

template<class State>
ApplyRandMutsTemplate<State>::ApplyRandMutsTemplate(
    State &state,
    AFLMidCalleeRef<State> abandon_entry
) : state(state),
    abandon_entry(abandon_entry) {}

template<class State>
AFLMidCalleeRef<State> ApplyRandMutsTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase
) {
    auto mutator = AFLMutatorTemplate<State>( *testcase->input, state );

    // call probablistic mutations
    // if they return true, then we should go to abandon_entry
    auto should_abandon_entry = this->CallSuccessors(mutator);
    if (should_abandon_entry) {
        this->SetResponseValue(true);
        return abandon_entry;
    }

    return this->GoToDefaultNext();
}

template<class State>
AbandonEntryTemplate<State>::AbandonEntryTemplate(State &state)
    : state(state) {}

template<class State>
AFLMidCalleeRef<State> AbandonEntryTemplate<State>::operator()(
    std::shared_ptr<typename State::OwnTestcase> testcase
) {
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

template<class State>
ExecutePUTTemplate<State>::ExecutePUTTemplate(State &state)
    : state(state) {}

template<class State>
NullableRef<HierarFlowCallee<bool(const u8*, u32)>> ExecutePUTTemplate<State>::operator()(
    const u8 *input,
    u32 len
) {
    ExitStatusFeedback exit_status;

    auto inp_feed = state.RunExecutorWithClassifyCounts(input, len, exit_status);
    CallSuccessors(input, len, inp_feed, exit_status);
    return GoToDefaultNext();
}

} // namespace fuzzuf::algorithm::afl::routine::other
