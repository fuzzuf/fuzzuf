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

#ifndef FUZZUF_INCLUDE_ALGORITHM_AFL_KSCHEDULER_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_AFL_KSCHEDULER_STATE_HPP

#include <memory>

#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/afl_kscheduler/option.hpp"
#include "fuzzuf/algorithms/afl_kscheduler/testcase.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"

namespace fuzzuf::algorithm::afl_kscheduler {

struct AFLKSchedulerState : public afl::AFLStateTemplate<AFLKSchedulerTestcase> {
  explicit AFLKSchedulerState(
      std::shared_ptr<const afl::AFLSetting> setting,
      std::shared_ptr<executor::AFLExecutorInterface> executor,
      std::unique_ptr<optimizer::HavocOptimizer> &&havoc_optimizer) :
    afl::AFLStateTemplate<AFLKSchedulerTestcase>(
      setting, executor, std::move( havoc_optimizer )
    ) {}
};

}

#endif

