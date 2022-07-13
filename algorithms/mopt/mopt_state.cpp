#include "fuzzuf/algorithms/mopt/mopt_state.hpp"
#include "fuzzuf/utils/random.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"
#include "fuzzuf/algorithms/mopt/mopt_setting.hpp"

namespace fuzzuf::algorithm::mopt {

MOptState::MOptState(
    std::shared_ptr<const MOptSetting> setting,
    std::shared_ptr<executor::AFLExecutorInterface> executor,
    std::unique_ptr<optimizer::Optimizer<u32>>&& mutop_optimizer
) : afl::AFLStateTemplate<MOptTestcase>(setting, executor, std::move(mutop_optimizer)),
    setting(setting)
{
    UpdateSpliceCycles(); // init
}

MOptState::~MOptState() {}

void MOptState::UpdateSpliceCycles() {
    splice_cycles_limit = fuzzuf::utils::random::Random<u32>(option::GetSpliceCyclesLow<option::MOptTag>(), option::GetSpliceCyclesUp<option::MOptTag>());
}

}
