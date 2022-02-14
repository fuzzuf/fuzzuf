#include "fuzzuf/algorithms/ijon/ijon_fuzzer.hpp"

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/ijon/ijon_hierarflow_routines.hpp"

namespace fuzzuf::algorithm::ijon {

IJONFuzzer::IJONFuzzer(std::unique_ptr<IJONState>&& moved_state) 
    : AFLFuzzerTemplate<IJONState>(std::move(moved_state)) 
{
    state->max_dir = state->setting->out_dir / "ijon_max";
    Util::CreateDir(state->max_dir.string());

    for (u32 i=0; i<option::GetMaxMapSize<option::IJONTag>(); i++) {
        state->all_inputs.emplace_back(
            state->input_set.CreateOnDisk(
                state->max_dir / std::to_string(i)
            )
        );
    }
}

IJONFuzzer::~IJONFuzzer() {}

void IJONFuzzer::BuildFuzzFlow() {
    // IJON uses two different flows depending on random numbers.
    // We construct these as fuzz_loop (AFL's one) and ijon_fuzz_loop

    // Construct AFL's hierarchical flow
    {
        using namespace afl::routine::other;
        using namespace afl::routine::mutation;
        using namespace afl::routine::update;
    
        using routine::other::PrintAflIsSelected;
        using routine::update::UpdateMax;

        using hierarflow::CreateNode;
        using hierarflow::CreateDummyParent;
        
        // Create the head node
        fuzz_loop = CreateDummyParent<void(void)>();

        // middle nodes(steps done before and after actual mutations)
        auto select_seed = CreateNode<SelectSeedTemplate<IJONState>>(*state);
        auto cull_queue  = CreateNode<CullQueueTemplate<IJONState>>(*state);

        // The original IJON inserts logging here to tell that 
        // AFL's flow is selected this time.
        auto print_afl_is_selected = CreateNode<PrintAflIsSelected>();

        auto abandon_node = CreateNode<AbandonEntryTemplate<IJONState>>(*state);
        
        auto consider_skip_mut = CreateNode<ConsiderSkipMutTemplate<IJONState>>(*state);
        auto retry_calibrate = CreateNode<RetryCalibrateTemplate<IJONState>>(*state, *abandon_node);
        auto trim_case = CreateNode<TrimCaseTemplate<IJONState>>(*state, *abandon_node);
        auto calc_score = CreateNode<CalcScoreTemplate<IJONState>>(*state);
        auto apply_det_muts  = CreateNode<ApplyDetMutsTemplate<IJONState>>(*state, *abandon_node);
        auto apply_rand_muts = CreateNode<ApplyRandMutsTemplate<IJONState>>(*state, *abandon_node);
        
        // actual mutations
        auto bit_flip1 = CreateNode<BitFlip1WithAutoDictBuildTemplate<IJONState>>(*state);
        auto bit_flip_other = CreateNode<BitFlipOtherTemplate<IJONState>>(*state);
        auto byte_flip1 = CreateNode<ByteFlip1WithEffMapBuildTemplate<IJONState>>(*state);
        auto byte_flip_other = CreateNode<ByteFlipOtherTemplate<IJONState>>(*state);
        auto arith = CreateNode<ArithTemplate<IJONState>>(*state);
        auto interest = CreateNode<InterestTemplate<IJONState>>(*state);
        auto user_dict_overwrite = CreateNode<UserDictOverwriteTemplate<IJONState>>(*state);
        auto user_dict_insert = CreateNode<UserDictInsertTemplate<IJONState>>(*state);
        auto auto_dict_overwrite = CreateNode<AutoDictOverwriteTemplate<IJONState>>(*state);
        auto havoc = CreateNode<HavocTemplate<IJONState>>(*state);
        // IJON changes a constant for some reason
        auto splicing = CreateNode<SplicingTemplate<IJONState>>(*state); 
        
        // execution
        auto execute = CreateNode<ExecutePUTTemplate<IJONState>>(*state);
        
        // updates corresponding to mutations
        auto normal_update = CreateNode<NormalUpdateTemplate<IJONState>>(*state);
        // IJON's update should be executed even in AFL's flow
        auto update_max = CreateNode<UpdateMax>(*state); 
        auto construct_auto_dict = CreateNode<ConstructAutoDictTemplate<IJONState>>(*state);
        auto construct_eff_map = CreateNode<ConstructEffMapTemplate<IJONState>>(*state);
     
        fuzz_loop << (
             cull_queue
          || select_seed
        );
    
        select_seed << (
             consider_skip_mut
          || print_afl_is_selected
          || retry_calibrate
          || trim_case
          || calc_score
          || apply_det_muts << (
                 bit_flip1 << execute << (
                                     normal_update 
                                  || construct_auto_dict 
                                  || update_max
                              )
              || bit_flip_other << execute.HardLink() << (
                                         normal_update.HardLink() 
                                      || update_max.HardLink()
                                   )
              || byte_flip1 << execute.HardLink() << (
                                         normal_update.HardLink()
                                      || construct_eff_map
                                      || update_max.HardLink()
                               )
              || byte_flip_other << execute.HardLink() << (
                                         normal_update.HardLink()
                                      || update_max.HardLink()
                                    )
              || arith << execute.HardLink() << (
                                         normal_update.HardLink()
                                      || update_max.HardLink()
                                    )
              || interest << execute.HardLink() << (
                                         normal_update.HardLink()
                                      || update_max.HardLink()
                             )
              || user_dict_overwrite << execute.HardLink() << (
                                             normal_update.HardLink()
                                          || update_max.HardLink()
                                        )
              || auto_dict_overwrite << execute.HardLink() << (
                                             normal_update.HardLink()
                                          || update_max.HardLink()
                                        )
             )
           || apply_rand_muts << (
                   havoc << execute.HardLink() << (
                                   normal_update.HardLink()
                                || update_max.HardLink()
                            )
                || splicing << execute.HardLink() << (
                                   normal_update.HardLink()
                                || update_max.HardLink()
                               )
              )
           || abandon_node
        );   
    }

    // Construct IJON's hierarchical flow
    {
        using namespace ijon::routine::other;
        using namespace ijon::routine::mutation;
        using namespace ijon::routine::update;

        using AFLSelectSeed = afl::routine::other::SelectSeedTemplate<IJONState>;
        using CullQueue = afl::routine::other::CullQueueTemplate<IJONState>;
        using ExecutePUT = afl::routine::other::ExecutePUTTemplate<IJONState>;
        using NormalUpdate = afl::routine::update::NormalUpdateTemplate<IJONState>;

        using hierarflow::CreateNode;
        using hierarflow::CreateDummyParent;

        // Create the head node
        ijon_fuzz_loop = CreateDummyParent<void(void)>();

        // middle nodes(steps done before and after actual mutations)
        
        auto cull_queue  = CreateNode<CullQueue>(*state);

        // When IJON's flow is taken, AFL's seed queue is not used.
        // However, the original IJON nevertheless loads and skips AFL's "queue_cur"...
        auto skip_afl_queue = CreateNode<AFLSelectSeed>(*state);

        auto select_seed = CreateNode<SelectSeed>(*state);

        // actual mutations
        auto max_havoc = CreateNode<MaxHavoc>(*state);
        
        // execution
        auto execute = CreateNode<ExecutePUT>(*state);
        
        // updates corresponding to mutations
        auto normal_update = CreateNode<NormalUpdate>(*state);
        auto update_max = CreateNode<UpdateMax>(*state);

        ijon_fuzz_loop << (
               cull_queue
            || skip_afl_queue
            || select_seed << max_havoc << execute << (normal_update || update_max)
        );
    }
}

bool IJONFuzzer::IjonShouldSchedule(void) {
    if (state->nonempty_inputs.size() == 0) return false;
    using fuzzuf::algorithm::afl::util::UR;
    return UR(100, state->rand_fd) > 20;
}

void IJONFuzzer::OneLoop(void) {
    if (!state->setting->ignore_finds && IjonShouldSchedule()) {
        ijon_fuzz_loop();
    } else {
        fuzz_loop();
    }
}

} // namespace fuzzuf::algorithm::ijon
