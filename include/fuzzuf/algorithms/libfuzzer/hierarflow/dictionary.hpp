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
 * @file dictionary.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_DICTIONARY_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_DICTIONARY_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/mutator_std_arg_order.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class StaticDict
 * @brief Insert or Overwrite value selected from the dictionary defined at the
 * node creation to the input specified by the Path. This node takes standard
 * mutator parameters( rng, input, max length and mutation history ).
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Dict Dictionary Type. Dictinary Type must be a container of
 * BasicDictionaryEntry (reference container type) or compatible type.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Dict, typename Path>
class StaticDict {};
template <typename R, typename... Args, typename Dict, typename Path>
class StaticDict<R(Args...), Dict, Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * All arguments are transfered to constructor of the dictionary
   */
  template <typename... T>
  StaticDict(T &&...args) : dict(std::forward<T>(args)...) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticDict", enter)
    Path()([&](auto &&...sorted) { mutator::Dictionary(sorted..., dict); },
           std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(StaticDict)
  }

 private:
  Dict dict;
};
namespace standard_order {
template <typename T>
using StaticDictStdArgOrderT = decltype(T::rng && T::input && T::max_length &&
                                        T::mutation_history && T::dict_history);
template <typename F, typename Dict, typename Ord>
using StaticDict = libfuzzer::StaticDict<F, Dict, StaticDictStdArgOrderT<Ord>>;
}  // namespace standard_order

/**
 * @class DynamicDict
 * @brief Insert or Overwrite value selected from the dictionary specified by
 * the Path to the input specified by the Path. This node takes 5 paths, 4 for
 * standard mutator parameters( rng, input, max length and mutation history )
 * and 1 for dictionary.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(DynamicDict,
                                                      mutator::Dictionary)
namespace standard_order {
template <typename T>
using DynamicDictStdArgOrderT =
    decltype(T::rng && T::input && T::max_length && T::mutation_history &&
             T::dict_history && T::dict);
template <typename F, typename Ord>
using DynamicDict = libfuzzer::DynamicDict<F, DynamicDictStdArgOrderT<Ord>>;
}  // namespace standard_order

/**
 * @class UpdateDictionary
 * @brief Add dictionary history entries to the dictionary specified by the
 * Path. libFuzzer has "Parsistent Auto Dictionary" that is a dictionary
 * contains words effective to find new coverage. This dictionary need to be
 * updated when an execution result was inserted to corpus and those mutation
 * used dictionary words. The expected usage of this node is to update
 * persistent auto dictionary. This node takes 2 paths for dict and
 * dict_history.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(UpdateDictionary,
                                                      mutator::UpdateDictionary)
namespace standard_order {
template <typename T>
using UpdateDictionaryStdArgOrderT = decltype(T::dict && T::dict_history);
template <typename F, typename Ord>
using UpdateDictionary =
    libfuzzer::UpdateDictionary<F, UpdateDictionaryStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
