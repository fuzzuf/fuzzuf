#include "fuzzuf/algorithms/mopt/mopt_havoc.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/optimizer/keys.hpp"
#include "fuzzuf/logger/logger.hpp"

namespace fuzzuf::algorithm::mopt::havoc {

/**
 * @fn
 * This function represents the probability distributions of mutation operators in the havoc mutation of MOpt.
 * original implementation `select_algorithm` is from: https://github.com/puppet-meteor/MOpt-AFL/blob/master/MOpt/afl-fuzz.c#L397-L436
 */
u32 MOptHavocCaseDistrib::CalcValue() {
    // FIXME: replace this engine with our pRNG later to avoid being flooded with pRNGs.
    static std::random_device seed_gen;
    static std::mt19937 engine(seed_gen());

    const auto& extras = optimizer::Store::GetInstance().Get(optimizer::keys::Extras).value().get();
    const auto& a_extras = optimizer::Store::GetInstance().Get(optimizer::keys::AutoExtras).value().get();


    const auto& probability_now = optimizer::Store::GetInstance().Get(optimizer::keys::ProbabilityNow);
    const auto swarm_now = optimizer::Store::GetInstance().Get(optimizer::keys::SwarmNow);

    int operator_number = (extras.size() + a_extras.size()) < 2 ? NUM_CASE - 2 : NUM_CASE;

    double range_sele = (double)probability_now[swarm_now][operator_number - 1];
    double sele = ((double)(engine() % 10000) * 0.0001 * range_sele);

    int i_puppet, j_puppet = 0;

    for (i_puppet = 0; i_puppet < operator_number; i_puppet++) {
        if (unlikely(i_puppet == 0)) {
            if (sele < probability_now[swarm_now][i_puppet]) {
                break;
            }
        }
        else if (sele < probability_now[swarm_now][i_puppet]) {
            j_puppet = 1;
            break;
        }
    }

    if ((j_puppet == 1) && (sele < probability_now[swarm_now][i_puppet - 1])
            || (i_puppet + 1 < NUM_CASE && sele > probability_now[swarm_now][i_puppet + 1])) {
        ERROR("error select_algorithm (MOptHavocCaseDistrib::CalcValue)");
    }

    return i_puppet;
}

}