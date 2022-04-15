#include "fuzzuf/algorithms/mopt/mopt_fuzzer.hpp"

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"


namespace fuzzuf::algorithm::mopt {

MOptFuzzer::MOptFuzzer() {
    
}

void MOptFuzzer::BuildFuzzFlow(void) {
    // TODO: remove
    {
        using namespace afl::routine::other;
        using namespace afl::routine::mutation;
        using namespace afl::routine::update;

        using namespace hierarflow::CreateNode;
        using namespace hierarflow::CreateDummyParent;

        using namespace fuzzuf::algorithm::mopt::routine;

        // head node
        fuzz_loop = CreateDummyParent<void(void)>();

        // middle nodes(steps done before and after actual mutations)
        auto select_seed = CreateNode<SelectSeedTemplate<MOptState>>(*state);
        auto cull_queue  = CreateNode<CullQueueTemplate<MOptState>>(*state);

        auto abandon_node = CreateNode<AbandonEntryTemplate<MOptState>>(*state);
        auto abandon_entry_puppet = CreateNode<AbandonEntryPuppet>(*state);

        auto consider_skip_mut = CreateNode<ConsiderSkipMutTemplate<MOptState>>(*state);
        auto retry_calibrate = CreateNode<RetryCalibrateTemplate<MOptState>>(*state, *abandon_node);
        auto trim_case = CreateNode<TrimCaseTemplate<MOptState>>(*state, *abandon_node);
        auto calc_score = CreateNode<CalcScoreTemplate<MOptState>>(*state);
        auto apply_det_muts  = CreateNode<ApplyDetMutsTemplate<MOptState>>(*state, *abandon_node);
        auto apply_rand_muts = CreateNode<ApplyRandMutsTemplate<MOptState>>(*state, *abandon_node);

        // actual mutations
        auto bit_flip1 = CreateNode<BitFlip1WithAutoDictBuildTemplate<MOptState>>(*state);
        auto bit_flip_other = CreateNode<BitFlipOtherTemplate<MOptState>>(*state);
        auto byte_flip1 = CreateNode<ByteFlip1WithEffMapBuildTemplate<MOptState>>(*state);
        auto byte_flip_other = CreateNode<ByteFlipOtherTemplate<MOptState>>(*state);
        auto arith = CreateNode<ArithTemplate<MOptState>>(*state);
        auto interest = CreateNode<InterestTemplate<MOptState>>(*state);
        auto user_dict_overwrite = CreateNode<UserDictOverwriteTemplate<MOptState>>(*state);
        auto user_dict_insert = CreateNode<UserDictInsertTemplate<MOptState>>(*state);
        auto auto_dict_overwrite = CreateNode<AutoDictOverwriteTemplate<MOptState>>(*state);
        auto havoc = CreateNode<HavocTemplate<MOptState>>(*state);
        auto splicing = CreateNode<SplicingTemplate<MOptState>>(*state);

        // execution
        auto execute = CreateNode<ExecutePUTTemplate<MOptState>>(*state);

        // updates corresponding to mutations
        auto normal_update = CreateNode<NormalUpdateTemplate<MOptState>>(*state);
        auto construct_auto_dict = CreateNode<ConstructAutoDictTemplate<MOptState>>(*state);
        auto construct_eff_map = CreateNode<ConstructEffMapTemplate<MOptState>>(*state);

        fuzz_loop << (
                cull_queue
            || select_seed
        );

        select_seed << (
                consider_skip_mut
            || retry_calibrate
            || trim_case
            || calc_score
            || apply_det_muts << (
                    bit_flip1 << execute << (normal_update || construct_auto_dict)
                || bit_flip_other << execute.HardLink() << normal_update.HardLink()
                || byte_flip1 << execute.HardLink() << (normal_update.HardLink()
                                                    || construct_eff_map)
                || byte_flip_other << execute.HardLink() << normal_update.HardLink()
                || arith << execute.HardLink() << normal_update.HardLink()
                || interest << execute.HardLink() << normal_update.HardLink()
                || user_dict_overwrite << execute.HardLink() << normal_update.HardLink()
                || auto_dict_overwrite << execute.HardLink() << normal_update.HardLink()
                )
            || apply_rand_muts << (
                    havoc << execute.HardLink() << normal_update.HardLink()
                    || splicing << execute.HardLink() << normal_update.HardLink()
                )
            || abandon_node
        );
    }

    // Construct fuzz loop for pilot_fuzzing
    {

    }

    // Construct fuzz loop for core_fuzzing
    {

    }

    // Construct fuzz loop for pso_updating
    {

    }
}

void MOptFuzzer::OneLoop(void) {
    // no implementation for `normal_fuzz_one` as `limit_time_sig` is set to 1 in MOpt mode

    switch(state.key_module) {
        case 0:
            pilot_fuzzing();
            break;
        case 1:
            core_fuzzing();
            break;
        case 2:
            pso_updating();
            break;
    }
}

} // fuzzuf::algorithm::mopt