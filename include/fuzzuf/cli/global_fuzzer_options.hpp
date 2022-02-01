/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#pragma once

#include <string>
#include <optional>
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/filesystem.hpp"

struct GlobalFuzzerOptions {
    bool help;
    std::string fuzzer;                     // Required
    std::string in_dir;                     // Required; TODO: fs::path might be better
    std::string out_dir;                    // Required
    std::optional<u32> exec_timelimit_ms;   // Optional
    std::optional<u64> exec_memlimit;       // Optional
    Logger logger;                          // Required
    std::optional<fs::path> log_file;       // Optional

    // Default values
    GlobalFuzzerOptions() : 
        help(false),
        fuzzer("afl"), 
        in_dir("./seeds"), // FIXME: Assuming Linux
        out_dir("/tmp/fuzzuf-out_dir"), // FIXME: Assuming Linux
        exec_timelimit_ms(std::nullopt), // Specify no limits
        exec_memlimit(std::nullopt),
        logger(Logger::Stdout),
        log_file(std::nullopt)
        {};
};
