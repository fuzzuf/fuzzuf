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

#ifndef FUZZUF_INCLUDE_OPTIMIZER_SLOPT_OPTIMIZER_HPP
#define FUZZUF_INCLUDE_OPTIMIZER_SLOPT_OPTIMIZER_HPP

#include <algorithm>
#include <random>

#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/slopt/thompson_sampling.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::optimizer::slopt {

class SloptOptimizer : public HavocOptimizer {
 public:
  SloptOptimizer(size_t num_arms, size_t max_file_size,
                 size_t max_batch_exponent);
  virtual ~SloptOptimizer();

  u32 CalcMutop(u32 batch_idx) override;

 private:
  u32 CalcBatchSize() override;
  void UpdateInternalState() override;

  u32 GetBucketIdxForSeedSize(u32 len);

  bool is_first_call = true;
  u32 prev_bucket_idx;
  u32 prev_pulled_mutop;
  u32 prev_pulled_batch;
  std::vector<ThompsonSampling> mut_bandits;
  std::vector<std::vector<ThompsonSampling>> bat_bandits;
};

}  // namespace fuzzuf::optimizer::slopt

#endif
