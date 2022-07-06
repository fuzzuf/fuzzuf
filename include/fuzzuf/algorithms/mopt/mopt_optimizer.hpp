#pragma once

#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/optimizer/pso.hpp"
#include "fuzzuf/optimizer/store.hpp"

namespace fuzzuf::optimizer {

using fuzzuf::mutator::NUM_CASE;

namespace keys {

const StoreKey<u32> LastSpliceCycle{"last_splice_cycle"};
const StoreKey<u64> NewTestcases{"new_testcases"};
const StoreKey<std::array<std::array<u64, NUM_CASE>, 2>> HavocOperatorFinds{
    "havoc_operator_finds"};  // [0]: pilot, [1]: core

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

class MOptOptimizer : public PSO<NUM_CASE, SwarmNum> {
 public:
  MOptOptimizer();
  ~MOptOptimizer();

  void Init();
  void UpdateLocalBest();
  void UpdateGlobalBest();
  void SetScore(size_t, double);
  void PSOUpdate();  // pso_updating
  void UpdateInertia();

  bool opt_minimize = false;

 private:
  std::array<MOptParticle, SwarmNum> swarm;
  int g_now = 0;
};

}  // namespace fuzzuf::optimizer