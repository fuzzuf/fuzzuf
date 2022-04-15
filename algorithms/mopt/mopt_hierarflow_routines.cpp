#include "fuzzuf/algorithms/mopt/mopt_hierarflow_routines.hpp"


namespace fuzzuf::algorithm::mopt::routine {

namespace other {

MOptMidCalleeRef AbandanEntryPuppet::operator() (std::shared_ptr<MOptTestcase> state) {
    // TODO: implement

/*

        abandon_entry_puppet:

            if (splice_cycle >= SPLICE_CYCLES_puppet)
                SPLICE_CYCLES_puppet = (UR(SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) + SPLICE_CYCLES_puppet_low);

*/

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


/*
            if (key_puppet == 1)
            {
                if (unlikely(queued_paths + unique_crashes > ((queued_paths + unique_crashes) * limit_time_bound + orig_hit_cnt_puppet)))
                {
                    key_puppet = 0;
                    cur_ms_lv = get_cur_time();
                    new_hit_cnt = queued_paths + unique_crashes;
                    orig_hit_cnt_puppet = 0;
                    last_limit_time_start = 0;
                }
            }

            if (unlikely(tmp_core_time > period_core))
            {
                total_pacemaker_time += tmp_core_time;
                tmp_core_time = 0;
                temp_puppet_find = total_puppet_find;
                new_hit_cnt = queued_paths + unique_crashes;

                u64 temp_stage_finds_puppet = 0;
                for (i = 0; i < operator_num; i++)
                {

                    core_operator_finds_puppet[i] = core_operator_finds_puppet_v2[i];
                    core_operator_cycles_puppet[i] = core_operator_cycles_puppet_v2[i];
                    temp_stage_finds_puppet += core_operator_finds_puppet[i];
                }

                key_module = 2;

                old_hit_count = new_hit_cnt;
            }
*/

    // ReponseValue should be set in previous steps, so do nothing here
    return this->GoToDefaultNext();
}

MOptMidCalleeRef ApplyMutDets::operator() (std::shared_ptr<MOptTestcase> state) {
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

    // TODO: implement
/*
    cur_ms_lv = get_cur_time();
    if (!(key_puppet == 0 && ((cur_ms_lv - last_path_time < limit_time_puppet) ||
                              (last_crash_time != 0 && cur_ms_lv - last_crash_time < limit_time_puppet) || last_path_time == 0)))
    {
        key_puppet = 1;
        goto pacemaker_fuzzing;
    } 
*/


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


}

}