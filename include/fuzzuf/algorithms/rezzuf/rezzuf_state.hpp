/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
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

#ifndef FUZZUF_INCLUDE_ALGORITHM_REZZUF_REZZUF_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_REZZUF_REZZUF_STATE_HPP

#include <memory>

#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_setting.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_testcase.hpp"
#include "fuzzuf/executor/afl_executor_interface.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::rezzuf {

using fuzzuf::utils::random::WalkerDiscreteDistribution;

struct RezzufState : public afl::AFLStateTemplate<RezzufTestcase> {
  explicit RezzufState(
      std::shared_ptr<const RezzufSetting> setting,
      std::shared_ptr<executor::AFLExecutorInterface> executor,
      std::unique_ptr<optimizer::HavocOptimizer> &&havoc_optimizer);

  std::shared_ptr<RezzufTestcase> AddToQueue(const std::string &fn,
                                             const u8 *buf, u32 len,
                                             bool passed_det) override;
  void UpdateBitmapScoreWithRawTrace(RezzufTestcase &testcase,
                                     const u8 *trace_bits,
                                     u32 map_size) override;
  bool SaveIfInteresting(const u8 *buf, u32 len,
                         feedback::InplaceMemoryFeedback &inp_feed,
                         feedback::ExitStatusFeedback &exit_status) override;
  u32 DoCalcScore(RezzufTestcase &testcase) override;
  void ShowStats(void) override;

  std::shared_ptr<const RezzufSetting> setting;
  std::shared_ptr<u32[]> n_fuzz;

  u32 prev_queued_items;
  std::unique_ptr<WalkerDiscreteDistribution<u32>> alias_probability;
};

}  // namespace fuzzuf::algorithm::rezzuf
#endif
