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
#include "fuzzuf/logger/log_file_logger.hpp"

#include <fstream>

#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::utils::LogFileLogger {
// Do not expose variables to outside of this module
bool stream_to_log_file = false;
std::ofstream log_file;

void Println(std::string message) {
  if (stream_to_log_file) {
    log_file << message << std::endl;
  }
}

void Init(fs::path log_file_path) {
  stream_to_log_file = true;
  log_file = std::ofstream(log_file_path.native());

  DEBUG(
      "[*] LogFileLogger::Init(): LogFileLogger = { stream_to_log_file=%s, "
      "log_file_path=%s }",
      stream_to_log_file ? "true" : "false", log_file_path.string().c_str());
}
}  // namespace fuzzuf::utils::LogFileLogger
