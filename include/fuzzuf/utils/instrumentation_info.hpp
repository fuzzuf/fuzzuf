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
 * @file executor.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_INSTRUMENTATION_INFO_HPP
#define FUZZUF_INCLUDE_UTILS_INSTRUMENTATION_INFO_HPP

#include <string>

namespace fuzzuf::utils {

struct InstrumentationInfo {
  bool instrumented = false;
  unsigned int major_version = 0u;
  unsigned int minor_version = 0u;
  unsigned int patch_version = 0u;
  bool write_afl_coverage = false;
  bool write_ijon_max = false;
  bool read_input_from_shared_memory =false;
};

InstrumentationInfo get_instrumentation_info( const std::string &filename );

}

#endif

