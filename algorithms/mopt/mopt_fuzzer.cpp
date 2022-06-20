#include "fuzzuf/algorithms/mopt/mopt_fuzzer.hpp"

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/algorithms/mopt/mopt_hierarflow_routines.hpp"


namespace fuzzuf::algorithm::mopt {


MOptFuzzer::MOptFuzzer(std::unique_ptr<MOptState>&& moved_state) 
    : AFLFuzzerTemplate<MOptState>(std::move(moved_state)) 
{}

MOptFuzzer::~MOptFuzzer() {}

void MOptFuzzer::BuildFuzzFlow(void) {
    {
        using namespace afl::routine::other;
        using namespace afl::routine::mutation;
        using namespace afl::routine::update;

        using hierarflow::CreateNode;
        using hierarflow::CreateDummyParent;

        using namespace fuzzuf::algorithm::mopt::routine;

        // head node
        fuzz_loop = CreateDummyParent<void(void)>();

        // middle nodes(steps done before and after actual mutations)
        auto select_seed = CreateNode<SelectSeedTemplate<MOptState>>(*state);
        auto cull_queue  = CreateNode<CullQueueTemplate<MOptState>>(*state);

        auto abandon_node = CreateNode<AbandonEntryTemplate<MOptState>>(*state);

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

        // MOpt-specific nodes
        using fuzzuf::algorithm::mopt::routine::other::CheckPacemakerThreshold;
        using fuzzuf::algorithm::mopt::routine::other::MOptUpdate;

        auto check_pacemaker = CreateNode<CheckPacemakerThreshold>(*state, *abandon_node);
        auto update_mopt = CreateNode<MOptUpdate>(*state);

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
            || check_pacemaker || apply_rand_muts << (
                    havoc << execute.HardLink() << normal_update.HardLink()
                    || splicing << execute.HardLink() << normal_update.HardLink()
                )
            || abandon_node
            || update_mopt
        );
    }
}

void MOptFuzzer::OneLoop(void) {
    fuzz_loop();
}

} // fuzzuf::algorithm::mopt