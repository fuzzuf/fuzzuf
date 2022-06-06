#pragma once

#include <memory>

#include "fuzzuf/exec_input/on_disk_exec_input.hpp"
#include "fuzzuf/algorithms/afl/afl_testcase.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"

namespace fuzzuf::algorithm::mopt {

struct MOptTestcase : public afl::AFLTestcase {
    using Tag = option::MOptTag;

    explicit MOptTestcase(std::shared_ptr<OnDiskExecInput> input);
    ~MOptTestcase();
};

} // namespace fuzzuf::algorithm::mopt
