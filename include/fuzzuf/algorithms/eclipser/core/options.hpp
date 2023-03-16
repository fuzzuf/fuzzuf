/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_OPTIONS_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_OPTIONS_HPP
#include <random>
#include <functional>
#include <string>
#include <cstdint>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>

namespace fuzzuf::algorithm::eclipser::options {
struct FuzzOption {
  int verbosity = 0;
  int timelimit = -1;
  std::string out_dir;
  std::string sync_dir;
  std::string target_prog;
  std::uint64_t exec_timeout = 500;
  Arch architecture = Arch::X64;
  bool fork_server = false;
  std::string input_dir;
  std::string arg;
  InputSource fuzz_source = StdInput{};
  int n_solve = 600;
  int n_spawn = 10;
  std::function<void(std::string &&)> sink;
  std::mt19937 rng;
};

}

#endif

