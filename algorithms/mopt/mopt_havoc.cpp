#include "fuzzuf/algorithms/mopt/mopt_havoc.hpp"

#include <random>

#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/optimizer/keys.hpp"

namespace fuzzuf::algorithm::mopt::havoc {

using fuzzuf::mutator::INSERT_AEXTRA;
using fuzzuf::mutator::INSERT_EXTRA;
using fuzzuf::mutator::OVERWRITE_WITH_AEXTRA;
using fuzzuf::mutator::OVERWRITE_WITH_EXTRA;

/**
 * @fn
 * This function represents the probability distributions of mutation operators
 * in the havoc mutation of MOpt. original implementation `select_algorithm` is
 * from:
 * https://github.com/puppet-meteor/MOpt-AFL/blob/master/MOpt/afl-fuzz.c#L397-L436
 */
u32 MOptHavocCaseDistrib::CalcValue() {
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

  auto weights(mopt->GetCurParticle());

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

}  // namespace fuzzuf::algorithm::mopt::havoc
