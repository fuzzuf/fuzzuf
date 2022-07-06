#pragma once

#include <memory>

#include "fuzzuf/algorithms/afl/afl_testcase.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"
#include "fuzzuf/exec_input/on_disk_exec_input.hpp"

namespace fuzzuf::algorithm::mopt {

using fuzzuf::exec_input::OnDiskExecInput;

struct MOptTestcase : public afl::AFLTestcase {
  using Tag = fuzzuf::algorithm::mopt::option::MOptTag;

  explicit MOptTestcase(std::shared_ptr<OnDiskExecInput> input);
  ~MOptTestcase();
};

}  // namespace fuzzuf::algorithm::mopt
