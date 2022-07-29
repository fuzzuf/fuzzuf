#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"

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

MOptParticle::MOptParticle() {}
MOptParticle::~MOptParticle() {}

MOptOptimizer::MOptOptimizer() {
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::NewTestcases, (u64)0);
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::HavocOperatorFinds);
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::SelectedCaseHistogram);
  fuzzuf::optimizer::Store::GetInstance().InitKey(
      fuzzuf::optimizer::keys::LastSpliceCycle, (u32)0);

  for (auto& p : swarm) {
    for (auto& pos : p.position)
      pos = fuzzuf::utils::random::Random<double>(min_position, max_position);
    p.velocity.fill(0);
  }

  idx = 0;
  time = 0;

  UpdateInertia();
}

MOptOptimizer::~MOptOptimizer() {}

void MOptOptimizer::SetScore(size_t i, double score) {
  auto& p = swarm[idx];
  p.fitness[i] = score;
}

void MOptOptimizer::UpdateLocalBest() {
  auto& p = swarm[idx];

  if (unlikely(time == 0)) {
    for (size_t i = 0; i < p.fitness.size(); i++) {
      p.best_fitness[i] = p.fitness[i];
      p.best_position[i] = p.position[i];
    }
  }

  for (size_t i = 0; i < p.fitness.size(); i++) {
    if (p.fitness[i] > p.best_fitness[i]) {
      p.best_fitness[i] = p.fitness[i];
      p.best_position[i] = p.position[i];
    }
  }
}

void MOptOptimizer::UpdateGlobalBest() {
  if (unlikely(time == 0)) {
    // TODO?
  }

  std::array<u64, NUM_CASE> havoc_operator_dist;
  havoc_operator_dist.fill(0);

  for (size_t i = 0; i < havoc_operator_finds[0].size(); i++) {
    havoc_operator_dist[i] =
        havoc_operator_finds[0][i] + havoc_operator_finds[1][i];
  }

  std::discrete_distribution<u32> dist(havoc_operator_dist.begin(),
                                       havoc_operator_dist.end());
  std::vector<double> prob = dist.probabilities();

  for (size_t i = 0; i < prob.size(); i++) {
    best_position[i] = prob[i];
  }
}

void MOptOptimizer::UpdateInertia() {
  w = (W_INIT - W_END) * (G_MAX - g_now) / G_MAX + W_END;
  ++g_now %= G_MAX;
}

bool MOptOptimizer::IncrementSwarmIdx() {
  idx++;
  idx %= swarm.size();
  return idx == 0;
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

  auto weights(swarm[idx].best_position);

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
