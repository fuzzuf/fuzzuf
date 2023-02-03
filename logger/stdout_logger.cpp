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
#include "fuzzuf/logger/stdout_logger.hpp"

#include <iostream>

namespace fuzzuf::utils::StdoutLogger {
// Do not expose variables to outside of this module
bool stream_to_stdout = true;  // Default

void Println(std::string message) {
  if (stream_to_stdout) {
    std::cout << message << std::endl;
  }
}

void Enable() { stream_to_stdout = true; }

void Disable() {
  stream_to_stdout = false;

  // Flush messages that has not yet been output
  std::cout << std::flush;
}
}  // namespace fuzzuf::utils::StdoutLogger
