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

namespace fuzzuf::cli {

/**
 * @class ExecutorKind
 * @brief Represents an executor type for CLI.
 */
class ExecutorKind {
public:
    enum Kind {
        UNKNOWN = 0, // Unknown Executor Type
        NATIVE, // Native Executor (e.g. NativeLinuxExecutor)
        QEMU, // QEMU Executor
        CORESIGHT, // CoreSight Executor
        FRIDA // FRIDA Executor
    };

    ExecutorKind() = default;

    constexpr ExecutorKind(Kind kind) : kind(kind) {}
    // Allow switch case.
    constexpr operator Kind() const { return kind; }
    // Prevent if (executor_kind) usage.
    explicit operator bool() = delete;

    const char *c_str() const {
        switch (kind) {
            case Kind::NATIVE:
                return "native";
            case Kind::QEMU:
                return "qemu";
            case Kind::CORESIGHT:
                return "coresight";
            case Kind::FRIDA:
                return "frida";
            default:
                return "unknown";
        }
    }

private:
    Kind kind;
};

std::istream& operator>>(std::istream& in, ExecutorKind& executor);

} // namespace fuzzuf::cli

struct GlobalFuzzerOptions {
    bool help;
    std::string fuzzer;                     // Required
    std::string in_dir;                     // Required; TODO: fs::path might be better
    std::string out_dir;                    // Required
    fuzzuf::cli::ExecutorKind executor;     // Optional
    std::optional<fs::path> proxy_path;     // Optional
    std::optional<u32> exec_timelimit_ms;   // Optional
    std::optional<u32> exec_memlimit;       // Optional
    Logger logger;                          // Required
    std::optional<fs::path> log_file;       // Optional

    // Default values
    GlobalFuzzerOptions() : 
        help(false),
        fuzzer("afl"), 
        in_dir("./seeds"), // FIXME: Assuming Linux
        out_dir("/tmp/fuzzuf-out_dir"), // FIXME: Assuming Linux
        executor(fuzzuf::cli::ExecutorKind::NATIVE),
        proxy_path(std::nullopt),
        exec_timelimit_ms(std::nullopt), // Specify no limits
        exec_memlimit(std::nullopt),
        logger(Logger::Stdout),
        log_file(std::nullopt)
        {};
};
