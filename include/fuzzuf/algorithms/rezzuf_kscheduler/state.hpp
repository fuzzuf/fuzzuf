/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */

#ifndef FUZZUF_INCLUDE_ALGORITHM_REZZUF_KSCHEDULER_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_REZZUF_KSCHEDULER_STATE_HPP

#include <memory>

#include "fuzzuf/utils/random.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/option.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_setting.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

struct State : public afl::AFLStateTemplate<Testcase> {
  explicit State(
      std::shared_ptr<const rezzuf::RezzufSetting> setting,
      std::shared_ptr<executor::AFLExecutorInterface> executor,
      std::unique_ptr<optimizer::HavocOptimizer> &&havoc_optimizer);

  std::shared_ptr<Testcase> AddToQueue(const std::string &fn,
                                             const u8 *buf, u32 len,
                                             bool passed_det) override;
  void UpdateBitmapScoreWithRawTrace(Testcase &testcase,
                                     const u8 *trace_bits,
                                     u32 map_size) override;
  bool SaveIfInteresting(const u8 *buf, u32 len,
                         feedback::InplaceMemoryFeedback &inp_feed,
                         feedback::ExitStatusFeedback &exit_status) override;
  double DoCalcScore(Testcase &testcase) override;
  void ShowStats(void) override;

  std::shared_ptr<const rezzuf::RezzufSetting> setting;
  std::shared_ptr<u32[]> n_fuzz;

  u32 prev_queued_items;
  std::unique_ptr<fuzzuf::utils::random::WalkerDiscreteDistribution<u32>> alias_probability;
};

}

#endif

