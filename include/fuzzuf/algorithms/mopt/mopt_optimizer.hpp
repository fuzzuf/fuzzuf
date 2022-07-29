#pragma once

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
  bool IncrementSwarmIdx();

  u32 CalcValue() override;

  std::array<std::array<u64, NUM_CASE>, 2>
      havoc_operator_finds;  // 0: pilot, 1: core

 private:
  void UpdatePositions();
  void UpdateVelocities();

  size_t idx = 0;
  std::uint64_t time = 0;
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