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
 * @file update_max_length.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_UPDATE_MAX_LENGTH_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_UPDATE_MAX_LENGTH_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class UpdateMaxLength
 * @brief increase max length of input depending on fuzzing status.
 *
 * The node takes 3 path for current max length, current runs count and last
 * corpus update run.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct UpdateMaxLength {};
template <typename R, typename... Args, typename Path>
class UpdateMaxLength<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * All arguments are transfered to constructor of the append value
   */
  template <typename... TArgs>
  UpdateMaxLength(std::size_t max_length_, std::size_t len_control_)
      : max_length(max_length_), len_control(len_control_) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("UpdateMaxLength", enter)
    Path()(
        [&](auto &&current_max_length, auto &&count,
            auto &&last_corpus_update_run) {
          if (current_max_length < max_length &&
              count - last_corpus_update_run >
                  len_control * lflog(current_max_length)) {
            current_max_length = std::min(
                max_length, current_max_length + lflog(current_max_length));
            last_corpus_update_run = count;
            std::cout << "update max length : " << current_max_length
                      << std::endl;
          }
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(UpdateMaxLength)
  }

 private:
  std::size_t max_length;
  std::size_t len_control;
};
namespace standard_order {
template <typename T>
using UpdateMaxLengthStdArgOrderT =
    decltype(T::max_length && T::count && T::last_corpus_update_run);
template <typename F, typename Ord>
using UpdateMaxLength =
    libfuzzer::UpdateMaxLength<F, UpdateMaxLengthStdArgOrderT<Ord>>;
}  // namespace standard_order
}  // namespace fuzzuf::algorithm::libfuzzer
#endif
