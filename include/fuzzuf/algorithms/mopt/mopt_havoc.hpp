

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_HAVOC_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_HAVOC_HPP

#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/optimizer/store.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"


namespace fuzzuf::algorithm::mopt::havoc {




class MOptHavocCaseDistrib : public optimizer::Optimizer<u32> {
public:
    MOptHavocCaseDistrib();
    ~MOptHavocCaseDistrib();

    u32 CalcValue() override;

    const u32 SwarmNum = 5;
};


} // namespace fuzzuf::algorithm::mopt::havoc


namespace fuzzuf::optimizer::keys {

using MOptHavocCaseDistrib = fuzzuf::algorithm::mopt::havoc::MOptHavocCaseDistrib;

const StoreKey<double[MOptHavocCaseDistrib::SwarmNum][NUM_CASE]> ProbabilityNow {"probability_now"};
const StoreKey<int> SwarmNow {"swarm_now"};


} // namespace fuzzuf::optimizer::keys



#endif
