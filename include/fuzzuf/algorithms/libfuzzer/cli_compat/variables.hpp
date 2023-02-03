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
 * @file variables.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CLI_VARIABLES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CLI_VARIABLES_HPP

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/dictionary.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/common_types.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::libfuzzer {
struct Variables {
  State state;
  FullCorpus corpus;
  std::minstd_rand rng;
  std::array<std::vector<std::uint8_t>, 3u>
      input;  // { input, crossover, mask }
  std::size_t max_input_size = 0u;
  MutationHistory mutation_history;
  dictionary::StaticDictionary persistent_auto_dict;
  dictionary::DictionaryHistory<dictionary::StaticDictionary> dict_history;
  InputInfo exec_result;
  coverage_t coverage;
  std::size_t count = 0u;
  std::chrono::system_clock::time_point begin_date;
  std::size_t last_corpus_update_run = 0u;
  std::vector<fuzzuf::executor::LibFuzzerExecutorInterface> executors;
  std::size_t executor_index = 0u;
  std::vector<fuzzuf::utils::mapped_file_t> symcc_out;
  unsigned int stuck_count = 0u;
};
namespace sp = utils::struct_path;
struct Order {
  using V = Variables;
  using Ranges = std::array<std::vector<std::uint8_t>, 3u>;
  using Dict = dictionary::StaticDictionary;
  using DictHistory = dictionary::DictionaryHistory<Dict>;
  using ElapsedTimeClock = std::chrono::system_clock::time_point;
  using Executors = std::vector<fuzzuf::executor::LibFuzzerExecutorInterface>;
  constexpr static auto arg0 = sp::root / sp::arg<0>;
  constexpr static auto state = arg0 / sp::mem<V, State, &V::state>;
  constexpr static auto create_info =
      state / sp::mem<State, FuzzerCreateInfo, &State::create_info>;
  constexpr static auto config =
      create_info /
      sp::mem<FuzzerCreateInfo, Config, &FuzzerCreateInfo::config>;
  constexpr static auto corpus = arg0 / sp::mem<V, FullCorpus, &V::corpus>;
  constexpr static auto rng = arg0 / sp::mem<V, std::minstd_rand, &V::rng>;
  constexpr static auto input =
      arg0 / sp::mem<V, Ranges, &V::input> / sp::elem<0u>;
  constexpr static auto max_length =
      arg0 / sp::mem<V, std::size_t, &V::max_input_size>;
  constexpr static auto mutation_history =
      arg0 / sp::mem<V, MutationHistory, &V::mutation_history>;
  constexpr static auto crossover =
      arg0 / sp::mem<V, Ranges, &V::input> / sp::elem<1u>;
  constexpr static auto dict =
      arg0 / sp::mem<V, Dict, &V::persistent_auto_dict>;
  constexpr static auto dict_history =
      arg0 / sp::mem<V, DictHistory, &V::dict_history>;
  constexpr static auto exec_result =
      arg0 / sp::mem<V, InputInfo, &V::exec_result>;
  constexpr static auto coverage = arg0 / sp::mem<V, coverage_t, &V::coverage>;
  constexpr static auto output = sp::root / sp::ident<output_t>;
  constexpr static auto count = arg0 / sp::mem<V, std::size_t, &V::count>;
  constexpr static auto begin_date =
      arg0 / sp::mem<V, ElapsedTimeClock, &V::begin_date>;
  constexpr static auto mask =
      arg0 / sp::mem<V, Ranges, &V::input> / sp::elem<2u>;
  constexpr static auto last_corpus_update_run =
      arg0 / sp::mem<V, std::size_t, &V::last_corpus_update_run>;
  constexpr static auto use_afl_coverage =
      create_info /
      sp::mem<FuzzerCreateInfo, bool, &FuzzerCreateInfo::use_afl_coverage>;
  constexpr static auto executors = arg0 / sp::mem<V, Executors, &V::executors>;
  constexpr static auto executor_index =
      arg0 / sp::mem<V, std::size_t, &V::executor_index>;
  constexpr static auto added_to_corpus =
      exec_result / sp::mem<InputInfo, bool, &InputInfo::added_to_corpus>;
  constexpr static auto symcc_out =
      arg0 /
      sp::mem<V, std::vector<fuzzuf::utils::mapped_file_t>, &V::symcc_out>;
  constexpr static auto symcc_target_offset =
      create_info / sp::mem<FuzzerCreateInfo, std::size_t,
                            &FuzzerCreateInfo::symcc_target_offset>;
  constexpr static auto stuck_count =
      arg0 / sp::mem<V, unsigned int, &V::stuck_count>;
  constexpr static auto symcc_freq =
      create_info /
      sp::mem<FuzzerCreateInfo, unsigned int, &FuzzerCreateInfo::symcc_freq>;
};
}  // namespace fuzzuf::algorithm::libfuzzer

#endif
