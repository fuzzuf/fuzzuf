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

#include "fuzzuf/optimizer/slopt/slopt_optimizer.hpp"

#include <vector>

#include "fuzzuf/optimizer/keys.hpp"
#include "fuzzuf/optimizer/store.hpp"

namespace fuzzuf::optimizer::slopt {

SloptOptimizer::SloptOptimizer(size_t num_arms, size_t max_file_size,
                               size_t max_batch_exp)
    : HavocOptimizer(),
      mut_bandits(GetBucketIdxForSeedSize(max_file_size) + 1,
                  ThompsonSampling(num_arms)),
      bat_bandits(GetBucketIdxForSeedSize(max_file_size) + 1,
                  std::vector<ThompsonSampling>(
                      num_arms, ThompsonSampling(max_batch_exp + 1))) {
  Store::GetInstance().InitKey(optimizer::keys::LastHavocFinds, (u64)0);
  Store::GetInstance().InitKey(optimizer::keys::SizeOfMutatedSeed, (u32)0);
  Store::GetInstance().InitKey(optimizer::keys::IsMutopBanned,
                               std::vector<bool>(num_arms));
}

SloptOptimizer::~SloptOptimizer() {}

u32 SloptOptimizer::GetBucketIdxForSeedSize(u32 len) {
  if (len <= 100) return 0;
  if (len <= 1000) return 1;
  if (len <= 10000) return 2;
  if (len <= 100000) return 3;
  return 4;
}

u32 SloptOptimizer::CalcBatchSize() {
  u32 len = Store::GetInstance().Get(optimizer::keys::SizeOfMutatedSeed, true);
  prev_bucket_idx = GetBucketIdxForSeedSize(len);

  const auto& is_mutop_banned =
      Store::GetInstance().GetMutRef(optimizer::keys::IsMutopBanned, true);
  prev_pulled_mutop = mut_bandits[prev_bucket_idx].PullArm(is_mutop_banned);
  prev_pulled_batch =
      bat_bandits[prev_bucket_idx][prev_pulled_mutop].PullArm({});

  return 1u << prev_pulled_batch;
}

u32 SloptOptimizer::CalcMutop([[maybe_unused]] u32 batch_idx) {
  return prev_pulled_mutop;
}

void SloptOptimizer::UpdateInternalState() {
  if (is_first_call) {
    is_first_call = false;
    return;
  }

  const bool is_mut_succeeded =
      Store::GetInstance().Get(optimizer::keys::LastHavocFinds, true) > 0;
  mut_bandits[prev_bucket_idx].AddResult(prev_pulled_mutop, is_mut_succeeded);
  bat_bandits[prev_bucket_idx][prev_pulled_mutop].AddResult(prev_pulled_batch,
                                                            is_mut_succeeded);
}

}  // namespace fuzzuf::optimizer::slopt
