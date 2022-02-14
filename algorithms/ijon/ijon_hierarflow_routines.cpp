#include "fuzzuf/algorithms/ijon/ijon_hierarflow_routines.hpp"

#include "fuzzuf/logger/stdout_logger.hpp"
#include "fuzzuf/algorithms/ijon/ijon_option.hpp"
#include "fuzzuf/algorithms/ijon/ijon_havoc.hpp"
#include "fuzzuf/algorithms/ijon/shared_data.hpp"

namespace fuzzuf::algorithm::ijon::routine {

namespace other {

SelectSeed::SelectSeed(struct IJONState& state) : state(state) {}

NullableRef<HierarFlowCallee<void(void)>> SelectSeed::operator()(void) {
    StdoutLogger::Println("scheduled max input!!!!");

    u32 idx = afl::util::UR(state.nonempty_inputs.size(), state.rand_fd);
    auto& selected_input = *state.nonempty_inputs[idx];
    StdoutLogger::Println("schedule: " + selected_input.GetPath().string());

    state.orig_perf = 100;

    // Unlike AFL, selected_input is never modified.
    // So we can immediately load it with mmap.
    selected_input.LoadByMmap();

    auto mutator = IJONMutator( selected_input, state );
    CallSuccessors(mutator);

    selected_input.Unload();
    
    return GoToDefaultNext();
}

PrintAflIsSelected::PrintAflIsSelected() {}

IJONMidCalleeRef PrintAflIsSelected::operator()(std::shared_ptr<IJONTestcase>) {
    StdoutLogger::Println("scheduled normal input!!!!");
    return GoToDefaultNext();
}

} // other

namespace mutation {

using HavocBase = afl::routine::mutation::HavocBaseTemplate<IJONState>;
using IJONMutCaleeRef = afl::routine::mutation::AFLMutCalleeRef<IJONState>;

MaxHavoc::MaxHavoc(IJONState &state) : HavocBase(state) {}

IJONMutCalleeRef MaxHavoc::operator()(IJONMutator& mutator) {
    if (DoHavoc(
              mutator,
              havoc::IJONHavocCaseDistrib,
              havoc::IJONCustomCases,
              "ijon-max", "ijon-max",
              state.orig_perf,
              afl::option::GetHavocCycles(state),
              afl::option::STAGE_HAVOC)) {
        SetResponseValue(true);
        return GoToParent();
    }

    return GoToDefaultNext();
}

} // mutation

namespace update {

using IJONUpdCalleeRef = afl::routine::update::AFLUpdCalleeRef;

UpdateMax::UpdateMax(IJONState &state) : state(state) {}

static void StoreMaxInput(IJONState &state, u32 idx, const u8 *data, u32 len) {
    // NOTE: is it no problem to overwrite/unload `all_inputs[idx]`, 
    // even though this input can be still loaded in IJON's flow?
    // The answer is yes because Mutator copies inputs to its own buffer,
    // which means modifying these inputs doesn't affect Mutator.
    // If Mutator's implementation is changed, then we have to 
    // add to ExecInput a member function that checks loaded or unloaded,
    // and use OverwriteThenUnload and OverwriteKeepingLoaded accordingly.
    state.all_inputs[idx]->OverwriteThenUnload(data, len);
 
    fs::path copy_fn = 
          state.max_dir / Util::StrPrintf("finding_%lu_%lu", 
                                            state.num_updates,
                                            time(NULL));

    state.all_inputs[idx]->Copy(copy_fn);
    state.num_updates++;
}

IJONUpdCalleeRef UpdateMax::operator()(
    const u8 *buf,
    u32 len,
    InplaceMemoryFeedback& inp_feed,
    ExitStatusFeedback &exit_status
) {
    // Originally, this procedure is done in save_if_interesting.
    // And the update occurs only if the following condition is not met.
    if (exit_status.exit_reason != state.crash_mode) return GoToDefaultNext();

    bool should_minify = len > 512;

    auto lambda = 
    [this, &should_minify, buf, len](const u8* trace_bits, u32 /*unused*/) {
        auto* shared = reinterpret_cast<const SharedData*>(trace_bits);
        for (u32 i=0; i<option::GetMaxMapSize<option::IJONTag>(); i++) {
            bool need_update = false;

            if (shared->afl_max[i] > state.max_map[i]) {
                need_update = true;

                if (state.max_map[i] == 0) {
                    // This i-th input will be nonempty shortly,
                    // so let's push it to nonempty_inputs.
                    state.nonempty_inputs.emplace_back(
                        state.all_inputs[i]
                    );
                }

                state.max_map[i] = shared->afl_max[i];
                StdoutLogger::Println(
                    Util::StrPrintf("updated maxmap %d: %lx (len: %ld)", 
                                    i, state.max_map[i], len)
                );
            } else if (
                   should_minify 
                && shared->afl_max[i] == state.max_map[i]
                && len < state.all_inputs[i]->GetLen()
            ) {
                need_update = true;
                StdoutLogger::Println(
                    Util::StrPrintf("minimized maxmap %d: %lx (len: %ld)", 
                                    i, state.max_map[i], len)
                );
            }

            if (need_update) StoreMaxInput(state, i, buf, len);
        }
    };

    inp_feed.ShowMemoryToFunc(lambda);
    return GoToDefaultNext();
}

} // update

} // fuzzuf::algorithm::ijon::routine
