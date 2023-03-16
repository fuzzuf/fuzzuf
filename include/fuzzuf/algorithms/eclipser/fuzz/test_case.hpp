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
 * @file test_case.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_FUZZ_TEST_CASE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_FUZZ_TEST_CASE_HPP

#include <string>
#include <functional>
#include <fuzzuf/utils/filesystem.hpp>
#include <fuzzuf/algorithms/eclipser/core/options.hpp>
#include <fuzzuf/algorithms/eclipser/core/seed.hpp>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>

namespace fuzzuf::algorithm::eclipser::test_case {

void Initialize(
  const fs::path &out_dir
);
void PrintStatistics(
  const std::function<void(std::string &&)> &sink
);
void EnableRoundStatistics();
void DisableRoundStatistics();
int GetRoundTestCaseCount();
void IncrTestCaseCount();
void ResetRoundTestCaseCount();
void Save(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seeds,
  Signal exit_sig,
  CoverageGain cov_gain
);

}

#endif

