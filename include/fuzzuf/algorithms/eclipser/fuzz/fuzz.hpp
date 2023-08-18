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
 * @file fuzz.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_FUZZ_FUZZ_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_FUZZ_FUZZ_HPP
#include <functional>
#include <string>
#include <random>
#include <fuzzuf/algorithms/eclipser/core/options.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/seed_queue.hpp>

namespace fuzzuf::algorithm::eclipser {

void FuzzOnce(
  const std::function<void(std::string &&)> &sink,
  std::mt19937 &rng,
  const options::FuzzOption &opt,
  seed_queue::SeedQueue &seed_queue,
  int &n
); 

void FuzzUntilEmpty(
  const std::function<void(std::string &&)> &sink,
  std::mt19937 &rng,
  const options::FuzzOption &opt
);

void FuzzLoop(
  const std::function<void(std::string &&)> &sink,
  std::mt19937 &rng,
  const options::FuzzOption &opt
);

}

#endif

