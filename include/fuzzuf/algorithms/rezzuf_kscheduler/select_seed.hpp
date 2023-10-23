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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_REZZUF_KSCHEDULER_SELECT_SEED_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_REZZUF_KSCHEDULER_SELECT_SEED_HPP

#include <memory>
#include <cstdint>
#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/option.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

struct SelectSeed
    : public hierarflow::HierarFlowRoutine<
          void(void), bool(std::shared_ptr<Testcase>)> {
 public:
  SelectSeed(State &state_) : state( state_ ) {}

  utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>> operator()(void);

 private:
  State &state;
  std::uint64_t prev_queued = 0;
};

}  // namespace fuzzuf::algorithm::rezzuf_kscheduler

#endif
