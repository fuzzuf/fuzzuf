#pragma once

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/optimizer/pso.hpp"
#include "fuzzuf/utils/random.hpp"

#include <random>
#include <algorithm>


namespace fuzzuf::optimizer {

template<size_t Demention>
Particle<Demention>::Particle(){};

template<size_t Demention>
Particle<Demention>::~Particle(){};

template<size_t Demention, size_t ParticleNum>
PSO<Demention, ParticleNum>::PSO(
    double min_position,
    double max_position,
    double min_velocity,
    double max_velocity,
    double w,
    double c1,
    double c2
) : min_position(min_position),
    max_position(max_position),
    min_velocity(min_velocity),
    max_velocity(max_velocity),
    w(w), c1(c1), c2(c2) {}

template<size_t Demention, size_t ParticleNum>
PSO<Demention, ParticleNum>::~PSO() {}

template<size_t Demention, size_t ParticleNum>
void
PSO<Demention, ParticleNum>::Init() {
    for (auto& p : swarm) {
        for (auto& pos : p.position) pos = fuzzuf::utils::random::Random<double>(min_position, max_position);
        p.velocity.fill(0);
    }

    idx = 0;
    time = 0;
}


template<size_t Demention, size_t ParticleNum>
std::array<double, Demention>
PSO<Demention, ParticleNum>::GetCurParticle() {
    return swarm[idx].best_position;
}

template<size_t Demention, size_t ParticleNum>
void
PSO<Demention, ParticleNum>::SetScore(double score) {
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

template<size_t Demention, size_t ParticleNum>
std::array<double, Demention>
PSO<Demention, ParticleNum>::CalcValue() {
    return best_position;
}


template<size_t Demention, size_t ParticleNum>
void
PSO<Demention, ParticleNum>::UpdatePositions() {
    auto& p = swarm[idx];

    for (size_t i = 0; i < Demention; i++) {
        double pos = p.position[i] + p.velocity[i];
        pos = std::min(pos, max_position);
        pos = std::max(pos, min_position);

        p.position[i] = pos;
    }
}

template<size_t Demention, size_t ParticleNum>
void
PSO<Demention, ParticleNum>::UpdateVelocities() {
    auto& p = swarm[idx];

    for (size_t i = 0; i < Demention; i++) {
        double v = w * p.velocity[i]
                            + c1 * fuzzuf::utils::random::Random<double>(0, 1) * (p.best_position[i] - p.position[i])
                            + c2 * fuzzuf::utils::random::Random<double>(0, 1) * (best_position[i] - p.position[i]);
        v = std::min(v, max_velocity);
        v = std::max(v, min_velocity);

        p.velocity[i] = v;
    }
}

template<size_t Demention, size_t ParticleNum>
void
PSO<Demention, ParticleNum>::UpdateLocalBest() {
    auto& p = swarm[idx];

    if (unlikely(time == 0)) {
        p.best_position = p.position;
        p.best_fitness = p.fitness;
        return;
    }

    if (p.fitness < p.best_fitness ^ !opt_minimize) { // not when optimize to maximize
        p.best_position = p.position;
        p.best_fitness = p.fitness;
    }
}

template<size_t Demention, size_t ParticleNum>
void
PSO<Demention, ParticleNum>::UpdateGlobalBest() {
    if (unlikely(time == 0)) {
        best_fitness = swarm[0].best_fitness;
        best_position = swarm[0].best_position;
    }

    for (auto p : swarm) {
        if (best_fitness < p.best_fitness ^ !opt_minimize) { // not when optimizer to maximize
            best_fitness = p.best_fitness;
            best_position = p.best_position;
        }
    }
}

} // namespace fuzzuf::optimizer