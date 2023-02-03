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

#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"

#include <algorithm>
#include <iterator>
#include <random>
#include <vector>

#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/optimizer/keys.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::optimizer {

using fuzzuf::mutator::INSERT_AEXTRA;
using fuzzuf::mutator::INSERT_EXTRA;
using fuzzuf::mutator::OVERWRITE_WITH_AEXTRA;
using fuzzuf::mutator::OVERWRITE_WITH_EXTRA;

MOptParticle::MOptParticle() {
  fitness.fill(0);
  best_fitness.fill(0);
}

MOptParticle::~MOptParticle() {}

MOptOptimizer::MOptOptimizer()
    : min_position(0.05), max_position(1), min_velocity(0), max_velocity(1) {
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::NewTestcases, (u64)0);
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::HavocOperatorFinds);
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::SelectedCaseHistogram);
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::LastSpliceCycle, (u32)0);
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::LastHavocFinds, (u64)0);

  // initialize
  accum_havoc_operator_finds[MOptMode::CoreMode].fill(0);
  accum_havoc_operator_finds[MOptMode::PilotMode].fill(0);
  accum_selected_case_histogram[MOptMode::CoreMode].fill(0);
  accum_selected_case_histogram[MOptMode::PilotMode].fill(0);
  best_position.fill(0);
  best_fitness = 0;
  swarm_fitness.fill(0);
  pacemaker_hit_cnt = 0;

  for (auto& p : swarm) {
    for (size_t i = 0; i < p.fitness.size(); i++) {
      p.best_fitness[i] = p.fitness[i];
      p.best_position[i] = p.position[i];
    }

    for (auto& pos : p.position)
      pos = fuzzuf::utils::random::Random<double>(min_position, max_position);
    p.velocity.fill(0);
  }

  idx = 0;
  g_now = 0;

  UpdateInertia();
}

MOptOptimizer::~MOptOptimizer() {}

void MOptOptimizer::SetScore(size_t i, double score) {
  auto& p = swarm[idx];
  p.fitness[i] = score;
}

void MOptOptimizer::SetSwarmFitness(double fitness) {
  swarm_fitness[idx] = fitness;
}

void MOptOptimizer::UpdateBestSwarmIdx() {
  best_idx = std::distance(
      swarm_fitness.begin(),
      std::max_element(swarm_fitness.begin(), swarm_fitness.end()));
}

void MOptOptimizer::UpdateLocalBest() {
  auto& p = swarm[idx];

  for (size_t i = 0; i < p.fitness.size(); i++) {
    if (p.fitness[i] > p.best_fitness[i]) {
      p.best_fitness[i] = p.fitness[i];
      p.best_position[i] = p.position[i];
    }
  }
}

void MOptOptimizer::UpdateGlobalBest() {
  std::array<u64, NUM_CASE> havoc_operator_dist;
  havoc_operator_dist.fill(0);

  for (size_t i = 0; i < NUM_CASE; i++) {
    havoc_operator_dist[i] = accum_havoc_operator_finds[MOptMode::CoreMode][i] +
                             accum_havoc_operator_finds[MOptMode::PilotMode][i];
  }

  std::discrete_distribution<u32> dist(havoc_operator_dist.begin(),
                                       havoc_operator_dist.end());
  std::vector<double> prob = dist.probabilities();

  for (size_t i = 0; i < prob.size(); i++) {
    best_position[i] = prob[i];
  }
}

void MOptOptimizer::UpdateInertia() {
  const double W_INIT = 0.9;
  const double W_END = 0.3;
  const int G_MAX = 5000;

  ++g_now %= G_MAX;
  w = (W_END - W_INIT) * (G_MAX - g_now) / G_MAX + W_END;
}

size_t MOptOptimizer::NextSwarmIdx() {
  idx++;
  idx %= swarm.size();
  return idx;
}

u32 MOptOptimizer::CalcValue() {
  // FIXME: replace this engine with our pRNG later to avoid being flooded with
  // pRNGs.
  static std::random_device seed_gen;
  static std::mt19937 engine(seed_gen());

  const auto& extras = optimizer::Store::GetInstance()
                           .Get(optimizer::keys::Extras)
                           .value()
                           .get();
  const auto& a_extras = optimizer::Store::GetInstance()
                             .Get(optimizer::keys::AutoExtras)
                             .value()
                             .get();

  bool no_extras = extras.empty();
  bool no_aextras = a_extras.empty();

  auto weights(swarm[mode == MOptMode::PilotMode ? idx : best_idx].position);

  if (no_extras) {
    weights[INSERT_EXTRA] = 0;
    weights[OVERWRITE_WITH_EXTRA] = 0;
  }
  if (no_aextras) {
    weights[INSERT_AEXTRA] = 0;
    weights[OVERWRITE_WITH_AEXTRA] = 0;
  }

  std::discrete_distribution<u32> dists(weights.begin(), weights.end());

  return dists(engine);
}

void MOptOptimizer::UpdatePositions() {
  auto& p = swarm[idx];

  for (size_t i = 0; i < NUM_CASE; i++) {
    double pos = p.position[i] + p.velocity[i];
    pos = std::min(pos, max_position);
    pos = std::max(pos, min_position);

    p.position[i] = pos;
  }
}

void MOptOptimizer::UpdateVelocities() {
  auto& p = swarm[idx];

  for (size_t i = 0; i < NUM_CASE; i++) {
    double v = w * p.velocity[i] +
               fuzzuf::utils::random::Random<double>(0, 1) *
                   (p.best_position[i] - p.position[i]) +
               fuzzuf::utils::random::Random<double>(0, 1) *
                   (best_position[i] - p.position[i]);
    v = std::min(v, max_velocity);
    v = std::max(v, min_velocity);

    p.velocity[i] = v;
  }
}

}  // namespace fuzzuf::optimizer
