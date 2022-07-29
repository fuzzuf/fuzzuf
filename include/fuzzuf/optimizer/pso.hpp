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

#ifndef FUZZUF_INCLUDE_OPTIMIZER_PSO_HPP
#define FUZZUF_INCLUDE_OPTIMIZER_PSO_HPP

#include <array>
#include <cstdint>
#include <functional>

#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/optimizer/store.hpp"
// for Particle Swarm Optimization

namespace fuzzuf::optimizer {

namespace keys {}

template <size_t Dimension, size_t ParticleNum>
class PSO;

template <size_t Dimension>
class Particle {
 public:
  Particle();
  ~Particle();

  template <size_t _Dimension, size_t ParticleNum>
  friend class PSO;

 protected:
  std::array<double, Dimension> position;
  double fitness;
  std::array<double, Dimension> velocity;
  std::array<double, Dimension> best_position;
  double best_fitness;
};

template <size_t Dimension, size_t ParticleNum>
class PSO : public Optimizer<std::array<double, Dimension>> {
 public:
  PSO(double min_position, double max_position, double min_velocity,
      double max_velocity, double w = 0.729, double c1 = 1.49445,
      double c2 = 1.49445);
  ~PSO();

  void Init();
  std::array<double, Dimension> GetCurParticle();
  void SetScore(double);
  std::array<double, Dimension> CalcValue() override;  // return global best
  void UpdateLocalBest();
  void UpdateGlobalBest();

 protected:
  void UpdatePositions();
  void UpdateVelocities();

  size_t idx = 0;
  std::uint64_t time = 0;
  std::array<Particle<Dimension>, ParticleNum> swarm;

  // global best
  std::array<double, Dimension> best_position;
  double best_fitness;

  // constraints
  double min_position;
  double max_position;
  double min_velocity;
  double max_velocity;

  // parameters
  double w = 0.729;     // inertia weight
  double c1 = 1.49445;  // cognitive weight
  double c2 = 1.49445;  // social weight

  bool opt_minimize = true;
};

}  // namespace fuzzuf::optimizer

#include "fuzzuf/optimizer/templates/pso.hpp"

#endif
