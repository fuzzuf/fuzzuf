

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_HAVOC_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_HAVOC_HPP

#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/optimizer/store.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"

#include <memory>


namespace fuzzuf::algorithm::mopt::havoc {




class MOptHavocCaseDistrib : public optimizer::Optimizer<u32> {
public:
    MOptHavocCaseDistrib();
    ~MOptHavocCaseDistrib();

    u32 CalcValue() override;

    std::shared_ptr<optimizer::MOptOptimizer> mopt;
};


} // namespace fuzzuf::algorithm::mopt::havoc


namespace fuzzuf::optimizer::keys {

using MOptHavocCaseDistrib = fuzzuf::algorithm::mopt::havoc::MOptHavocCaseDistrib;



} // namespace fuzzuf::optimizer::keys



#endif
