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
 * @file counter_to_feature.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_COUNTER_TO_DEPTH_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_COUNTER_TO_DEPTH_HPP

namespace fuzzuf::algorithm::libfuzzer::feature {

// Given a non-zero Counter returns a number in the range [0,7].
/**
 * convert coverage counter value to lower 3bits of feature ID.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerTracePC.h#L213
 *
 * @tparam T Type of counter
 * @param counter Counter
 * @return lower 3bits of feature ID
 */
template <typename T>
unsigned int CounterToFeature(T counter) {
  // Returns a feature number by placing Counters into buckets as illustrated
  // below.
  //
  // Counter bucket: [1] [2] [3] [4-7] [8-15] [16-31] [32-127] [128+]
  // Feature number:  0   1   2    3     4       5       6       7
  //
  // This is a heuristic taken from AFL (see
  // http://lcamtuf.coredump.cx/afl/technical_details.txt).
  //
  // This implementation may change in the future so clients should
  // not rely on it.
  assert(counter);
  /**/ if (counter >= 128)
    return 7;
  else if (counter >= 32)
    return 6;
  else if (counter >= 16)
    return 5;
  else if (counter >= 8)
    return 4;
  else if (counter >= 4)
    return 3;
  else if (counter >= 3)
    return 2;
  else if (counter >= 2)
    return 1;
  else
    return 0;
}

}  // namespace fuzzuf::algorithm::libfuzzer::feature

#endif
