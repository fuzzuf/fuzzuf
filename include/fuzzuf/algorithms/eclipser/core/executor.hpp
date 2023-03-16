/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file executor.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_EXECUTOR_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_EXECUTOR_HPP

#include <cstdint>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>
#include <fuzzuf/algorithms/eclipser/core/branch_info.hpp>
#include <fuzzuf/algorithms/eclipser/core/options.hpp>
#include <fuzzuf/algorithms/eclipser/core/seed.hpp>
#include <fuzzuf/utils/filesystem.hpp>

namespace fuzzuf::algorithm::eclipser::executor {

void EnableRoundStatistics();
void DisableRoundStatistics();
int GetRoundExecs();
void IncrRoundExecs();
void ResetRoundExecs();
CoverageGain ParseCoverage( const fs::path &p );
BranchTrace ParseBranchTrace( const fs::path &p, std::uint64_t try_value, bool is_64bit );
fs::path SelectTracer( Tracer tracer, Arch arch );
fs::path BuildDir();
void Initialize(
  const options::FuzzOption &opt
);
std::pair< Signal, CoverageGain > GetCoverage(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed
);
std::tuple< Signal, CoverageGain, std::vector< BranchInfo > >
GetBranchTrace(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  const BigInt &try_val
);
std::tuple< Signal, CoverageGain, std::optional< BranchInfo > >
GetBranchInfo(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  const BigInt &try_val,
  const BranchPoint &targ_point
);
std::optional< BranchInfo > GetBranchInfoOnly(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  const BigInt &try_val,
  const BranchPoint &targ_point
);
std::vector< std::string > SplitCmdLineArg(
  const std::string &arg_str
);
Signal NativeExecute(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed
);

}

#endif

