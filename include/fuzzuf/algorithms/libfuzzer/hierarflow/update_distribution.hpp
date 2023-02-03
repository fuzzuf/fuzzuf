/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
/**
 * @file update_distribution.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_UPDATE_DISTRIBUTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_UPDATE_DISTRIBUTION_HPP
#include <memory>

#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/select_seed.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class UpdateDistribution
 * @brief Update probability of selecting each input in the corpus according to
 * the state of corpus. The node takes 3 path for state( to retrive configs
 * affecting to update ), corpus and RNG.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam llvm_version LLVM version. Probability calculation method varies
 * depending on LLVM version.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, Version llvm_version, typename Path>
struct UpdateDistribution {};
template <typename R, typename... Args, Version llvm_version, typename Path>
struct UpdateDistribution<R(Args...), llvm_version, Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @tparam Sink Type of sink_
   * @param sink_ Callback function with one string argument to output message
   */
  template <typename Sink>
  UpdateDistribution(std::size_t sparse_energy_updates_,
                     std::uint8_t max_mutation_factor_, Sink &&sink_)
      : sparse_energy_updates(sparse_energy_updates_),
        max_mutation_factor(max_mutation_factor_),
        sink(std::forward<Sink>(sink_)) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("UpdateDistribution",
                                                     enter)
    Path()(
        [&](auto &&...sorted) {
          select_seed::UpdateDistribution<llvm_version>(
              sorted..., sparse_energy_updates, max_mutation_factor, sink);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(UpdateDistribution)
  }

 private:
  std::size_t sparse_energy_updates;
  std::uint8_t max_mutation_factor;
  std::function<void(std::string &&)> sink;
};
namespace standard_order {
template <typename T>
using UpdateDistributionStdArgOrderT =
    decltype(T::state && T::corpus && T::rng);
template <typename F, Version llvm_version, typename Ord>
using UpdateDistribution =
    libfuzzer::UpdateDistribution<F, llvm_version,
                                  UpdateDistributionStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
