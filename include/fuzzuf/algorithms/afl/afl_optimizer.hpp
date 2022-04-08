#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"

class AFLOptimizer : OptimizerSet {
private:
    Optimizer<HavocCase> mutop;

public:
    AFLOptimizer();
    ~AFLOptimizer();
};