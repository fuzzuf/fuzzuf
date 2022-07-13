

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_HAVOC_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_HAVOC_HPP

#include <memory>

#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/optimizer/store.hpp"

namespace fuzzuf::algorithm::mopt::havoc {

class MOptHavocCaseDistrib : public optimizer::Optimizer<u32> {
 public:
  MOptHavocCaseDistrib(optimizer::MOptOptimizer*);
  ~MOptHavocCaseDistrib();

  u32 CalcValue() override;

  std::unique_ptr<optimizer::MOptOptimizer> mopt;
};

}  // namespace fuzzuf::algorithm::mopt::havoc

namespace fuzzuf::optimizer::keys {

using MOptHavocCaseDistrib =
    fuzzuf::algorithm::mopt::havoc::MOptHavocCaseDistrib;

}  // namespace fuzzuf::optimizer::keys

#endif
