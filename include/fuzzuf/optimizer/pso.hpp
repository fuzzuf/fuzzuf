#pragma once

#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/optimizer/store.hpp"

#include <functional>
#include <array>
#include <cstdint>
// for Particle Swarm Optimization

namespace fuzzuf::optimizer {

namespace keys {

}

template<size_t Demention, size_t ParticleNum>
class PSO;


template<size_t Demention>
class Particle {
public:
    Particle();
    ~Particle();

    template<size_t _Demention, size_t ParticleNum>
    friend class PSO;

protected:
    std::array<double, Demention> position;
    double fitness;
    std::array<double, Demention> velocity;
    std::array<double, Demention> best_position;
    double best_fitness;
};


template<size_t Demention, size_t ParticleNum>
class PSO : public Optimizer<std::array<double, Demention>> {
public:
    PSO(
        double min_position,
        double max_position,
        double min_velocity,
        double max_velocity,
        double w = 0.729,
        double c1 = 1.49445,
        double c2 = 1.49445
    );
    ~PSO();

    void Init();
    std::array<double, Demention> GetCurParticle();
    void SetScore(double);
    std::array<double, Demention> CalcValue() override; // return global best
    void UpdateLocalBest();
    void UpdateGlobalBest();

protected:
    void UpdatePositions();
    void UpdateVelocities();

    size_t idx = 0;
    std::uint64_t time = 0;
    std::array<Particle<Demention>, ParticleNum> swarm;

    // global best
    std::array<double, Demention> best_position;
    double best_fitness;

    // parameters
    double w = 0.729; // inertia weight
    double c1 = 1.49445; // cognitive weight
    double c2 = 1.49445; // social weight

    // constraints
    double min_position;
    double max_position;
    double min_velocity;
    double max_velocity;

    bool opt_minimize = true;
};


}

#include "fuzzuf/optimizer/templates/pso.hpp"
