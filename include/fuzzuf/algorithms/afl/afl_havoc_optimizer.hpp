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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_AFL_AFL_HAVOC_OPTIMIZER_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_AFL_AFL_HAVOC_OPTIMIZER_HPP

#include <memory>

#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::afl {

class AFLHavocOptimizer : public optimizer::HavocOptimizer {
 public:
  AFLHavocOptimizer(std::shared_ptr<optimizer::Optimizer<u32>> mutop_optimizer,
                    int havoc_stack_pow);
  virtual ~AFLHavocOptimizer();

  u32 CalcMutop(u32 batch_idx) override;

 private:
  u32 CalcBatchSize() override;
  void UpdateInternalState() override;

  std::shared_ptr<optimizer::Optimizer<u32>> mutop_optimizer;
  int havoc_stack_pow;
};

}  // namespace fuzzuf::algorithm::afl

#endif
