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

#ifndef FUZZUF_INCLUDE_OPTIMIZER_HAVOC_OPTIMIZER_HPP
#define FUZZUF_INCLUDE_OPTIMIZER_HAVOC_OPTIMIZER_HPP

#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::optimizer {

/**
 * @class HavocOptimizer
 * @brief Optimizer for two parameters used in `Mutator::Havoc`
 * @details This class will work as a base class in `Mutator::Havoc`.
 * It has three virtual methods:
 *  - `CalcBatchSize` should return the number of times mutation operators
 *    are applied to a single input.
 *  - `CalcMutop` should return an index of mutation operator that
 *     will be used for the `batch_idx`-th time out of `CalcBatchSize()` times.
 *  - `UpdateInternalState` should update its internal state.
 *     As `UpdateAndCalcBatch` suggests, this member function is called always
 *     before `CalcBatchSize` is called. Be careful that this function is called
 *     even before the first call of `CalcBatchSize()`.
 * If you want to implement a new algorithm that controls the two parameter,
 * you should define a new class that derives from this class.
 **/
class HavocOptimizer {
 public:
  HavocOptimizer() {}
  virtual ~HavocOptimizer() {}

  u32 UpdateAndCalcBatch() {
    UpdateInternalState();
    return CalcBatchSize();
  }

  virtual u32 CalcMutop(u32 batch_idx) = 0;

 private:
  virtual u32 CalcBatchSize() = 0;
  virtual void UpdateInternalState() = 0;
};

/**
 * @class ConstantBatchHavocOptimizer
 * @brief Wrapper for mutop optimizer
 * @note The lifetime of this class should be shorter than the given
 * `mutop_optimizer`. It is recommended to temporarily create an instance of
 * this class every time it's needed.
 */
class ConstantBatchHavocOptimizer : public HavocOptimizer {
 public:
  ConstantBatchHavocOptimizer(u32 batch_size, Optimizer<u32>& mutop_optimizer)
      : batch_size(batch_size), mutop_optimizer(mutop_optimizer) {}
  virtual ~ConstantBatchHavocOptimizer() {}

  u32 CalcMutop([[maybe_unused]] u32 batch_idx) override {
    return mutop_optimizer.CalcValue();
  }

 private:
  u32 CalcBatchSize() override { return batch_size; }
  void UpdateInternalState() override {}

  u32 batch_size;
  Optimizer<u32>& mutop_optimizer;
};

}  // namespace fuzzuf::optimizer

#endif
