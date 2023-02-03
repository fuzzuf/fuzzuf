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

#include "fuzzuf/algorithms/ijon/ijon_state.hpp"

#include "fuzzuf/executor/afl_executor_interface.hpp"

namespace fuzzuf::algorithm::ijon {

IJONState::IJONState(
    std::shared_ptr<const afl::AFLSetting> setting,
    std::shared_ptr<executor::IJONExecutorInterface> executor,
    std::unique_ptr<optimizer::HavocOptimizer>&& havoc_optimizer)
    : afl::AFLStateTemplate<IJONTestcase>(
          setting,
          // std::make_shared<executor::AFLExecutorInterface>(executor->ExposeExecutor()),
          std::make_shared<executor::AFLExecutorInterface>(executor),
          std::move(havoc_optimizer)),
      ijon_executor(executor) {}

IJONState::~IJONState() {}

}  // namespace fuzzuf::algorithm::ijon
