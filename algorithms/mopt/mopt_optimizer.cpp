#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"

#include <random>
#include <vector>


namespace fuzzuf::optimizer {

MOptParticle::MOptParticle() {}
MOptParticle::~MOptParticle() {}

MOptOptimizer::MOptOptimizer() : PSO(P_MIN, P_MAX, 0, 0, 0, 1, 1) {
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

    auto havoc_operator_finds = fuzzuf::optimizer::Store::GetInstance().Get(fuzzuf::optimizer::keys::HavocOperatorFinds);
    std::array<u64, NUM_CASE> havoc_operator_dist;
    havoc_operator_dist.fill(0);

    for (size_t i = 0; i < havoc_operator_finds[0].size(); i++) {
        havoc_operator_dist[i] = havoc_operator_finds[0][i] + havoc_operator_finds[1][i];
    }

    std::discrete_distribution<u32> dist(havoc_operator_dist.begin(), havoc_operator_dist.end());
    std::vector<double> prob = dist.probabilities();

    for (size_t i = 0; i < prob.size(); i++) {
        best_position[i] = prob[i];
    }
}

void MOptOptimizer::UpdateInertia() {
    PSO::w = (W_INIT - W_END) * (G_MAX - g_now) / G_MAX + W_END;
    ++g_now %= G_MAX;
}


}