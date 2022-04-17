#pragma once


#include "fuzzuf/algorithms/mopt/mopt_state.hpp"
#include "fuzzuf/utils/random.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"

namespace fuzzuf::algorithm::mopt {

MOptState::MOptState(
    std::shared_ptr<const afl::AFLSetting> setting,
    std::shared_ptr<executor::AFLExecutorInterface> executor,
    std::unique_ptr<optimizer::Optimizer<u32>>&& mutop_optimizer
) : afl::AFLStateTemplate<IJONTestcase>(setting, executor, std::move(mutop_optimizer))
{
    UpdateSpliceCycles();
}

void MOptState::UpdateSpliceCycles() {
    splice_cycles = fuzzuf::utils::random::Random<u32>(option::GetSpliceCyclesLow(), option::GetSpliceCyclesUp());
}

}