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
#include "fuzzuf/logger/logger.hpp"

#include "fuzzuf/exceptions.hpp"

namespace fuzzuf::utils {

RunLevel runlevel = FUZZUF_DEFAULT_RUNLEVEL;

std::string to_string(Logger v) {
  switch (v) {
    case Logger::LogFile:
      return "LogFile";
    case Logger::Flc:
      return "Flc";
    default:
      throw exceptions::logger_error(
          fuzzuf::utils::StrPrintf("Unknown Logger enum value: %d", v),
          __FILE__, __LINE__);
  }
}

}  // namespace fuzzuf::utils
