/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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

#ifndef FUZZUF_INCLUDE_OPTIMIZER_TEMPLATES_PSO_HPP
#define FUZZUF_INCLUDE_OPTIMIZER_TEMPLATES_PSO_HPP

#include <algorithm>
#include <random>

#include "fuzzuf/optimizer/pso.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::optimizer {

template <size_t Dimension>
Particle<Dimension>::Particle(){};

template <size_t Dimension>
Particle<Dimension>::~Particle(){};

template <size_t Dimension, size_t ParticleNum>
PSO<Dimension, ParticleNum>::PSO(double min_position, double max_position,
                                 double min_velocity, double max_velocity,
                                 double w, double c1, double c2)
    : min_position(min_position),
      max_position(max_position),
      min_velocity(min_velocity),
      max_velocity(max_velocity),
      w(w),
      c1(c1),
      c2(c2) {}

template <size_t Dimension, size_t ParticleNum>
PSO<Dimension, ParticleNum>::~PSO() {}

template <size_t Dimension, size_t ParticleNum>
void PSO<Dimension, ParticleNum>::Init() {
  for (auto& p : swarm) {
    for (auto& pos : p.position)
      pos = fuzzuf::utils::random::Random<double>(min_position, max_position);
    p.velocity.fill(0);
  }

  idx = 0;
  time = 0;
}

template <size_t Dimension, size_t ParticleNum>
std::array<double, Dimension> PSO<Dimension, ParticleNum>::GetCurParticle() {
  return swarm[idx].best_position;
}

template <size_t Dimension, size_t ParticleNum>
void PSO<Dimension, ParticleNum>::SetScore(double score) {
  auto& p = swarm[idx];
  p.fitness = score;
  UpdateLocalBest();

  idx++;
  idx %= swarm.size();

  if (idx == 0) {
    UpdateGlobalBest();
    time++;
  }
}

template <size_t Dimension, size_t ParticleNum>
std::array<double, Dimension> PSO<Dimension, ParticleNum>::CalcValue() {
  return best_position;
}

template <size_t Dimension, size_t ParticleNum>
void PSO<Dimension, ParticleNum>::UpdatePositions() {
  auto& p = swarm[idx];

  for (size_t i = 0; i < Dimension; i++) {
    double pos = p.position[i] + p.velocity[i];
    pos = std::min(pos, max_position);
    pos = std::max(pos, min_position);

    p.position[i] = pos;
  }
}

template <size_t Dimension, size_t ParticleNum>
void PSO<Dimension, ParticleNum>::UpdateVelocities() {
  auto& p = swarm[idx];

  for (size_t i = 0; i < Dimension; i++) {
    double v = w * p.velocity[i] +
               c1 * fuzzuf::utils::random::Random<double>(0, 1) *
                   (p.best_position[i] - p.position[i]) +
               c2 * fuzzuf::utils::random::Random<double>(0, 1) *
                   (best_position[i] - p.position[i]);
    v = std::min(v, max_velocity);
    v = std::max(v, min_velocity);

    p.velocity[i] = v;
  }
}

template <size_t Dimension, size_t ParticleNum>
void PSO<Dimension, ParticleNum>::UpdateLocalBest() {
  auto& p = swarm[idx];

  if (unlikely(time == 0)) {
    p.best_position = p.position;
    p.best_fitness = p.fitness;
    return;
  }

  if (p.fitness < p.best_fitness ^
      !opt_minimize) {  // not when optimize to maximize
    p.best_position = p.position;
    p.best_fitness = p.fitness;
  }
}

template <size_t Dimension, size_t ParticleNum>
void PSO<Dimension, ParticleNum>::UpdateGlobalBest() {
  if (unlikely(time == 0)) {
    best_fitness = swarm[0].best_fitness;
    best_position = swarm[0].best_position;
  }

  for (auto p : swarm) {
    if (best_fitness < p.best_fitness ^
        !opt_minimize) {  // not when optimizer to maximize
      best_fitness = p.best_fitness;
      best_position = p.best_position;
    }
  }
}

}  // namespace fuzzuf::optimizer

#endif
