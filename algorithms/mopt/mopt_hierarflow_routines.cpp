#include "fuzzuf/algorithms/mopt/mopt_hierarflow_routines.hpp"
#include "fuzzuf/optimizer/pso.hpp"
#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"

namespace fuzzuf::algorithm::mopt::routine {

namespace other {


MOptMidCalleeRef MOptUpdate::operator(std::shared_ptr<MOptTestcase> testcase) (){
    auto last_splice_cycle = fuzzuf::optimizer::Store::GetInstance().Get(fuzzuf::optimizer::keys::LastSpliceCycle);

    if (last_splice_cycle >= option::GetSpliceCycles(state)) {
        state.UpdateSpliceCycles();
    }

    if (state.packemaker_mode) {
        // TODO
    }

    auto new_testcases = fuzzuf::optimizer::Store::GetInstance().Get(fuzzuf::optimizer::keys::NewTestcases);
    auto havoc_operator_finds = fuzzuf::optimizer::Store::GetInstance().Get(fuzzuf::optimizer::keys::HavoOperatorFinds);
    auto selected_case_histogram = fuzzuf::optimizer::Store::GetInstance().Get(fuzzuf::optimizer::keys::SelectedCaseHistogram);

    // pilot mode (update local best)
    if (!state.core_mode) {
        if (new_testcases > option::GetPeriodPilot()) [[unlikely]] {
            for (size_t i = 0; i < selected_case_histogram.size(); i++) {
                double score = 0.0;
                if (selected_case_histogram[i] > 0) {
                    score = havoc_operator_finds[i] / selected_case_histogram[i];
                }
                state.mopt.SetScore(i, score);
            }
            state.mopt.UpdateLocalBest();
        }
    }

    // core mode (update global best)
    if (state.core_mode) {
        if (new_testcases > option::GetPeriodCore()) [[unlikely]] {
            state.mopt.UpdateGlobalBest();
        }
    }
}


CheckPacemakerThreshold::CheckPacemakerThreshold(
    MOptState &state,
    MOptMidCalleeRef abandon_entry
) : state(state), abandon_entry(abandon_entry) {}

MOptMidCalleeRef CheckPacemakerThreshold::operator(std::shared_ptr<MOptTestcase> testcase) (){
    u64 cur_ms_lv = Util::GetCurTimeMS();
    if (!(state.packemaker_mode == false
            && ((cur_ms_lv - state.last_path_time < state.setting.limit_time_puppet)
                || (state.last_crash_time != 0 && cur_ms_lv - state.last_crash_time < state.setting.limit_time_puppet)
                || (state.last_path_time == 0)))) {
        state.packemaker_mode = true;
        return abandon_entry;
    }
    return this->GoToDefaultNext();
}


} // namespace other


namespace mutation {

MOptHavoc::MOptHavoc() {}

bool MOptHavoc::DoHavoc(
    AFLMutatorTemplate<MOptState>& mutator,
    optimizer::Optimizer<u32> &mutop_optimizer,
    CustomCases custom_cases,
    const std::string &stage_name,
    const std::string &stage_short,
    u32 perf_score,
    s32 stage_max_multiplier, 
    int stage_idx    
) {
    state.stage_name = stage_name;
    state.stage_short = stage_short;
    state.stage_max = stage_max_multiplier * perf_score / state.havoc_div / 100;
    state.stage_cur_byte = -1;

    if (state.stage_max < option::GetHavocMin(state)) {
        state.stage_max = option::GetHavocMin(state);
    }

    u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;

    u64 havoc_queued = state.queued_paths;

    /* We essentially just do several thousand runs (depending on perf_score)
       where we take the input file and make random stacked tweaks. */

    for (state.stage_cur = 0; state.stage_cur < state.stage_max; state.stage_cur++) {
        using afl::util::UR;

        u32 use_stacking = 1 << (1 + UR(option::GetHavocStackPow2(state), state.rand_fd));

        state.stage_cur_val = use_stacking;
        mutator.Havoc(use_stacking, state.extras, state.a_extras, mutop_optimizer, custom_cases);

        auto& new_testcases = fuzzuf::optimizer::Store::GetInstance().GetMutRef(fuzzuf::optimizer::keys::NewTestcases);
        new_testcases++;

        u64 havoc_finds = state.queued_paths + state.unique_crashes;

        if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) return true;

        havoc_finds -= state.queued_paths + state.unique_crashes;

        if (havoc_finds > 0) [[unlikely]] {
            auto selected_case_histogram = fuzzuf::optimizer::Store::GetInstance().Get(fuzzuf::optimizer::keys::SelectedCaseHistogram);
            auto& havoc_operator_finds = fuzzuf::optimizer::Store::GetInstance().GetMutRef(fuzzuf::optimizer::keys::HavocOperatorFinds);
            for (size_t i = 0; i < selected_case_histogram.size(); i++) {
                if (selected_case_histogram[i] > 0) {
                    havoc_operator_finds[state.core_mode?1:0][i] += havoc_finds;
                }
            }
        }

        /* out_buf might have been mangled a bit, so let's restore it to its
           original size and shape. */

        mutator.RestoreHavoc();

        /* If we're finding new stuff, let's run for a bit longer, limits
           permitting. */

        if (state.queued_paths != havoc_queued) {
            if (perf_score <= option::GetHavocMaxMult(state) * 100) {
                state.stage_max *= 2;
                perf_score *= 2;
            }

            havoc_queued = state.queued_paths;
        }
    }

    u64 new_hit_cnt = state.queued_paths + state.unique_crashes;
    state.stage_finds[stage_idx] += new_hit_cnt - orig_hit_cnt;
    state.stage_cycles[stage_idx] += state.stage_max;

    return false;
}


Splicing::Splicing();

MOptMutCalleeRef Splicing::operator()(
    AFLMutatorTemplate<MOptState>& mutator
) {
    // Declare the alias just to omit "this->" in this function.
    auto& state = this->state;

    if (!state.use_splicing || state.setting->ignore_finds) {
        return this->GoToDefaultNext();
    }

    u32 splice_cycle = 0;
    while (splice_cycle++ < option::GetSpliceCycles(state)
        && state.queued_paths > 1
        && mutator.GetSource().GetLen() > 1) {

        /* Pick a random queue entry and seek to it. Don't splice with yourself. */

        u32 tid;
        do {
            using afl::util::UR;
            tid = UR(state.queued_paths, state.rand_fd);
        } while (tid == state.current_entry);

        /* Make sure that the target has a reasonable length. */

        while (tid < state.case_queue.size()) {
            if (state.case_queue[tid]->input->GetLen() >= 2 &&
                tid != state.current_entry) break;

            ++tid;
        }

        if (tid == state.case_queue.size()) continue;

        auto &target_case = *state.case_queue[tid];
        state.splicing_with = tid;

        /* Read the testcase into a new buffer. */

        target_case.input->Load();
        bool success = mutator.Splice(*target_case.input);
        target_case.input->Unload();

        if (!success) {
            continue;
        }

        using afl::dictionary::AFLDictData;

        if (this->DoHavoc(mutator,
                    *state.mutop_optimizer,
                    [](int, u8*&, u32&, const std::vector<AFLDictData>&, const std::vector<AFLDictData>&){},
                    Util::StrPrintf("splice %u", splice_cycle),
                    "splice",
                    state.orig_perf, option::GetSpliceHavoc(state),
                    option::STAGE_SPLICE)) {
            this->SetResponseValue(true);
            return this->GoToParent();
        }

        mutator.RestoreSplice();
    }
    fuzzuf::optimizer::Store::GetInstance().Set(fuzzuf::optimizer::keys::LastSpliceCycle, splice_cycle);

    return this->GoToDefaultNext();
}

} // namespace mutation

} // namespace fuzzuf::algorithm::mopt::routine