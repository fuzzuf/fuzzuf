#pragma once

#include <memory>

#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/mopt/mopt_havoc.hpp"
#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"
#include "fuzzuf/algorithms/mopt/mopt_setting.hpp"
#include "fuzzuf/algorithms/mopt/mopt_testcase.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"

namespace fuzzuf::algorithm::mopt {

struct MOptState : public afl::AFLStateTemplate<MOptTestcase> {
  explicit MOptState(std::shared_ptr<const mopt::MOptSetting> setting,
                     std::shared_ptr<executor::AFLExecutorInterface> executor,
                     std::shared_ptr<optimizer::MOptOptimizer>&& mopt);
  ~MOptState();

  void UpdateSpliceCycles();

  void ShowStats(void);

  bool pacemaker_mode = false;  // key_puppet: (0: false, 1: true)
  bool core_mode = false;       // key_module: (0: pilot, 1: core)

  u32 splice_cycles_limit = 0;

  std::shared_ptr<const MOptSetting> setting;
  std::shared_ptr<optimizer::MOptOptimizer> mopt;
};

}  // namespace fuzzuf::algorithm::mopt
