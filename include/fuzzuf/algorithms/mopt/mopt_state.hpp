#pragma once

#include <memory>

#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"
#include "fuzzuf/algorithms/mopt/mopt_testcase.hpp"

namespace fuzzuf::algorithm::mopt {

struct MOptState : public afl::AFLStateTemplate<MOptTestcase> {
    explicit MOptState(std::shared_ptr<const afl::AFLSetting> setting, std::shared_ptr<NativeLinuxExecutor> executor);
    ~MOptState();

    void UpdateSpliceCycles();

    int pacemaker_fuzzing = 0; // originally key_puppet
    int key_module = 0;

    u32 splice_cycles;
}

} // namespace fuzzuf::algorithm::mopt
