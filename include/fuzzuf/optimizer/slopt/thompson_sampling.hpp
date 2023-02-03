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

#ifndef FUZZUF_INCLUDE_OPTIMIZER_SLOPT_THOMPSON_SAMPLING_HPP
#define FUZZUF_INCLUDE_OPTIMIZER_SLOPT_THOMPSON_SAMPLING_HPP

#include <vector>

#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::optimizer::slopt {

// Thompson Sampling for binomial reward distribution
class ThompsonSampling {
 public:
  ThompsonSampling(size_t num_arms);

  size_t PullArm(const std::vector<bool>& is_arm_banned);
  void AddResult(size_t arm_idx, u8 reward);

 private:
  void AddNumSelected(size_t arm_idx);
  void AddReward(size_t arm_idx, u8 reward);

  size_t num_arms;
  std::vector<u64> num_selected;
  std::vector<u64> num_rewarded;
};

}  // namespace fuzzuf::optimizer::slopt

#endif
