/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
 * @file options.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_ECLIPSER_CLI_COMPAT_OPTIONS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_ECLIPSER_CLI_COMPAT_OPTIONS_HPP

#include <string>
#include <functional>
#include <boost/program_options.hpp>

#include "fuzzuf/algorithms/eclipser/core/options.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"


namespace fuzzuf::algorithm::eclipser {

auto CreateOptions(options::FuzzOption &dest)
    -> boost::program_options::options_description;

auto PostProcess(
  const boost::program_options::options_description &desc,
  int argc,
  const char *argv[],
  const cli::GlobalFuzzerOptions &global,
  std::function<void(std::string &&)> &&sink,
  options::FuzzOption &dest
) -> bool;

}

#endif

