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
 * @file mutator.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/mutator_std_arg_order.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/simple_function.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::libfuzzer {
/*
 * Make mutators callable from HierarFlow.
 */
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(EraseBytes,
                                                      mutator::EraseBytes)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(InsertByte,
                                                      mutator::InsertByte)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(
    InsertRepeatedBytes, mutator::InsertRepeatedBytes)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(ChangeByte,
                                                      mutator::ChangeByte)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(ChangeBit,
                                                      mutator::ChangeBit)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(ShuffleBytes,
                                                      mutator::ShuffleBytes)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(
    ChangeASCIIInteger, mutator::ChangeASCIIInteger)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(
    ChangeBinaryInteger, mutator::ChangeBinaryInteger)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(CopyPart,
                                                      mutator::CopyPart)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(Crossover,
                                                      mutator::Crossover)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(
    IncrementMutationsCount, mutator::IncrementMutationsCount)
FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_SIMPLE_FUNCTION(ToASCII, mutator::ToASCII)
namespace standard_order {
template <typename T>
using CrossoverStdArgOrderT = decltype(T::rng && T::input && T::max_length &&
                                       T::mutation_history && T::crossover);
template <typename T>
using ToASCIIStdArgOrderT = decltype(T::input);
template <typename T>
using IncrementMutationsCountStdArgOrderT =
    decltype(T::state && T::exec_result);
template <typename F, typename Ord>
using EraseBytes = libfuzzer::EraseBytes<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using InsertByte = libfuzzer::InsertByte<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using InsertRepeatedBytes =
    libfuzzer::InsertRepeatedBytes<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using ChangeByte = libfuzzer::ChangeByte<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using ChangeBit = libfuzzer::ChangeBit<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using ShuffleBytes = libfuzzer::ShuffleBytes<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using ChangeASCIIInteger =
    libfuzzer::ChangeASCIIInteger<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using ChangeBinaryInteger =
    libfuzzer::ChangeBinaryInteger<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using CopyPart = libfuzzer::CopyPart<F, MutatorStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using Crossover = libfuzzer::Crossover<F, CrossoverStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using IncrementMutationsCount = libfuzzer::IncrementMutationsCount<
    F, IncrementMutationsCountStdArgOrderT<Ord>>;
template <typename F, typename Ord>
using ToASCII = libfuzzer::ToASCII<F, ToASCIIStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
