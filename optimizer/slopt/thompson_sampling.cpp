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

#include "fuzzuf/optimizer/slopt/thompson_sampling.hpp"

#include <boost/math/distributions/beta.hpp>
#include <boost/random.hpp>
#include <random>

namespace fuzzuf::optimizer::slopt {

ThompsonSampling::ThompsonSampling(size_t _num_arms)
    : num_arms(_num_arms), num_selected(num_arms), num_rewarded(num_arms) {}

// FIXME: we should unify random engines.
namespace {

std::random_device rd;
boost::random::mt19937 rng(rd());

}  // namespace

size_t ThompsonSampling::PullArm(const std::vector<bool>& is_arm_banned) {
  double max_sampled = -1;
  size_t selected_idx = 0;

  for (size_t i = 0; i < num_arms; i++) {
    if (!is_arm_banned.empty() && is_arm_banned[i]) continue;

    u64 a = num_rewarded[i] + 1;
    u64 b = num_selected[i] - num_rewarded[i] + 1;

    boost::random::beta_distribution<> dist(a, b);
    double sampled = dist(rng);
    if (sampled > max_sampled) {
      max_sampled = sampled;
      selected_idx = i;
    }
  }

  return selected_idx;
}

void ThompsonSampling::AddNumSelected(size_t arm_idx) {
  ++num_selected[arm_idx];
}

void ThompsonSampling::AddReward(size_t arm_idx, u8 reward) {
  num_rewarded[arm_idx] += reward;
}

void ThompsonSampling::AddResult(size_t arm_idx, u8 reward) {
  AddNumSelected(arm_idx);
  AddReward(arm_idx, reward);
}

}  // namespace fuzzuf::optimizer::slopt
