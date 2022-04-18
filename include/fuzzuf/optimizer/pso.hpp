#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/optimizer/store.hpp"

#include <functional>
#include <array>

// for Particle Swarm Optimization

namespace fuzzuf::optimizer {

namespace keys {

}


template<size_t Demention>
class Particle {
public:
    Particle();
    ~Particle();

private:
    std::array<double, Demention> position;
    double fitness;
    std::array<double, Demention> velocity;
    std::array<double, Demention> best_position;
    double best_fitness;
};


template<size_t Demention, size_t ParticleNum>
class PSO : public Optimizer<std::array<double, Demention>> {
public:
    PSO(double, double, double, double, double, double, double);
    ~PSO();

    void Init();
    std::array<double, Demention> GetCurParticle();
    void SetScore(double);
    std::array<double, Demention> CalcValue() override; // return global best

private:
    void UpdatePositions();
    void UpdateVelocities();
    void UpdateLocalBest();
    void UpdateGlobalBest();

    size_t idx = 0;
    u64 time = 0;
    std::array<Particle<Demention>, ParticleNum> swarm;

    // global best
    Particle<Demention> best_position;
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
