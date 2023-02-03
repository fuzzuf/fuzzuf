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
 * @file afl_edge_cov_attacher.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_COVERAGE_AFL_EDGE_COV_ATTACHER_HPP
#define FUZZUF_INCLUDE_COVERAGE_AFL_EDGE_COV_ATTACHER_HPP

#include "fuzzuf/coverage/shm_cov_attacher.hpp"

namespace fuzzuf::coverage {

/**
 * @class AFLEdgeCovAttacher
 * @brief AFL-compatible hashed edge coverage attacher.
 */
class AFLEdgeCovAttacher : public ShmCovAttacher {
 public:
  static constexpr const char* SHM_ENV_VAR = "__AFL_SHM_ID";

  AFLEdgeCovAttacher(u32 map_size) : ShmCovAttacher(map_size) {}
  void SetupEnvironmentVariable(void) {
    ShmCovAttacher::SetupEnvironmentVariable(SHM_ENV_VAR);
  }
};

}  // namespace fuzzuf::coverage

#endif  // FUZZUF_INCLUDE_COVERAGE_AFL_EDGE_COV_ATTACHER_HPP
