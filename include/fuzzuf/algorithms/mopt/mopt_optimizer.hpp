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

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_OPTIMIZER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_OPTIMIZER_HPP

#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/optimizer/pso.hpp"
#include "fuzzuf/optimizer/store.hpp"

namespace fuzzuf::optimizer {

using fuzzuf::mutator::NUM_CASE;

namespace keys {

const StoreKey<u64> NewTestcases{"new_testcases"};

}  // namespace keys

const size_t SwarmNum = 5;
const double P_MAX = 1;
const double P_MIN = 0.05;
const double W_INIT = 0.9;
const double W_END = 0.3;
const int G_MAX = 5000;

enum MOptMode {
  CoreMode,
  PilotMode,
};

class MOptParticle : public Particle<NUM_CASE> {
 public:
  MOptParticle();
  ~MOptParticle();

  friend class MOptOptimizer;

 private:
  std::array<double, NUM_CASE> fitness;
  std::array<double, NUM_CASE> best_fitness;
};

class MOptOptimizer : public Optimizer<u32> {
 public:
  MOptOptimizer();
  ~MOptOptimizer();

  void Init();
  void UpdateLocalBest();
  void UpdateGlobalBest();
  void SetScore(size_t, double);
  void UpdateInertia();
  bool NextSwarmIdx();

  u32 CalcValue() override;

  std::array<std::array<u64, NUM_CASE>, 2>
      accum_havoc_operator_finds;  // 0: pilot, 1: core
  std::array<std::array<u64, NUM_CASE>, 2>
      accum_selected_case_histogram;  // 0: pilot, 1: core

  bool pacemaker_mode = false;  // key_puppet: (0: false, 1: true)
  MOptMode mode = MOptMode::PilotMode;

 private:
  void UpdatePositions();
  void UpdateVelocities();

  size_t idx;
  std::array<MOptParticle, SwarmNum> swarm;

  // global best
  std::array<double, NUM_CASE> best_position;
  double best_fitness;

  // parameter
  int g_now = 0;
  double w = 0;  // inertia weight

  double min_position = P_MIN;
  double max_position = P_MAX;
  double min_velocity = 0;
  double max_velocity = 1;
};

}  // namespace fuzzuf::optimizer

#endif
