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
 * @file config.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_CONFIG_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_CONFIG_HPP
#include <cstddef>

namespace fuzzuf::algorithm::eclipser {

/// Size of bitmap to measure edge coverage. Should be updated along with the
/// macros at Instrumentor/patches-*/eclipser.c
constexpr long BITMAP_SIZE = 0x10000l;

/// Synchronize the seed queue with AFL every SYNC_N iteration of fuzzing loop.
constexpr int SYNC_N = 10;

/// We will consider every ROUND_SIZE executions as a single round. A 'round' is
/// the unit of time for resource scheduling (cf. Scheduler.fs)
constexpr int ROUND_SIZE = 10000;
constexpr float SLEEP_FACTOR_MIN = 0.0f;
constexpr float SLEEP_FACTOR_MAX = 4.0f;

/// Minimum and maximum value for the execution timeout of target program. Note
/// that AFL uses 1000UL for EXEC_TIMEOUT_MAX, but we use a higher value since
/// Eclipser is a binary-based fuzzer. Note that this range is ignored when an
/// explicit execution timeout is given with '-e' option.
constexpr unsigned long EXEC_TIMEOUT_MIN = 400ul;
constexpr unsigned long EXEC_TIMEOUT_MAX = 4000ul;

/// Maximum length of chunk to try in grey-box concolic testing.
constexpr int MAX_CHUNK_LEN = 10;

/// The length of each input during the initialization of a seed. If the user
/// explicitly provided initial seed inputs, this parameter will not be used.
constexpr int INIT_INPUT_LEN = 16;

constexpr int MAX_INPUT_LEN = 1048576;

constexpr int BRANCH_COMB_WINDOW = 6;

}

#endif

