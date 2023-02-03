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
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_CLICOMPAT_VARIABLES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_CLICOMPAT_VARIABLES_HPP

#include "fuzzuf/algorithms/libfuzzer/cli_compat/variables.hpp"
#include "fuzzuf/algorithms/nezha/state.hpp"

namespace fuzzuf::algorithm::nezha {
/**
 * @class UsingOutputHashVariables
 * @brief Nezha specific variables
 */
struct Variables {
  libfuzzer::output_t output;
  trace_t trace;
  known_traces_t known_traces;
  status_t status;
  known_status_t known_status;
  outputs_t outputs;
  known_outputs_t known_outputs;
};

namespace sp = utils::struct_path;
/**
 * @class UsingStatusOrder
 * @brief Paths to the Nezha specific variables
 */
struct Order
    : public libfuzzer::Order {  // almost all variables required by libFuzzer
                                 // are located in same layout to libFuzzer
  using V = nezha::Variables;
  constexpr static auto ne =
      sp::root /
      sp::arg<1>;  // Nezha specific variables are located at second argument
  constexpr static auto output =
      ne / sp::mem<V, libfuzzer::output_t, &V::output>;
  constexpr static auto trace = ne / sp::mem<V, trace_t, &V::trace>;
  constexpr static auto known_traces =
      ne / sp::mem<V, known_traces_t, &V::known_traces>;
  constexpr static auto status = ne / sp::mem<V, status_t, &V::status>;
  constexpr static auto known_status =
      ne / sp::mem<V, known_status_t, &V::known_status>;
  constexpr static auto outputs = ne / sp::mem<V, outputs_t, &V::outputs>;
  constexpr static auto known_outputs =
      ne / sp::mem<V, known_outputs_t, &V::known_outputs>;
  constexpr static auto single_status =
      exec_result / sp::mem<libfuzzer::InputInfo, feedback::PUTExitReasonType,
                            &libfuzzer::InputInfo::status>;
  constexpr static auto added_to_corpus =
      exec_result / sp::mem<libfuzzer::InputInfo, bool,
                            &libfuzzer::InputInfo::added_to_corpus>;
};

}  // namespace fuzzuf::algorithm::nezha

#endif
