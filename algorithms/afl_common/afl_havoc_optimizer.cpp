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

#include "fuzzuf/algorithms/afl/afl_havoc_optimizer.hpp"

#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/optimizer/keys.hpp"
#include "fuzzuf/optimizer/store.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::afl {

AFLHavocOptimizer::AFLHavocOptimizer(
    std::shared_ptr<optimizer::Optimizer<u32>> _mutop_optimizer,
    int _havoc_stack_pow)
    : mutop_optimizer(_mutop_optimizer), havoc_stack_pow(_havoc_stack_pow) {}

AFLHavocOptimizer::~AFLHavocOptimizer() {}

u32 AFLHavocOptimizer::CalcMutop([[maybe_unused]] u32 batch_idx) {
  return mutop_optimizer->CalcValue();
}

u32 AFLHavocOptimizer::CalcBatchSize() {
  // FIXME: UR should be replaced with a new random number generator when it's
  // ready
  return 1 << (1 + util::UR(havoc_stack_pow, -1));
}

void AFLHavocOptimizer::UpdateInternalState() {}

}  // namespace fuzzuf::algorithm::afl
