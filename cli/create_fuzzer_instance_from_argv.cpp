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

#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"

#include "fuzzuf/cli/fuzzer_builder_register.hpp"
#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/log_file_logger.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/logger/stdout_logger.hpp"

namespace fuzzuf::cli {

std::unique_ptr<Fuzzer> CreateFuzzerInstanceFromArgv(int argc, const char **argv) {
    // Explicitly enable logging to stdout as Logger does not get confirmed before parsing command line options
    StdoutLogger::Enable();

    GlobalFuzzerOptions global_options;

    GlobalArgs global_args = {.argc = argc, .argv = argv};
    FuzzerArgs fuzzer_args =
        ParseGlobalOptionsForFuzzer(global_args, /* &mut */ global_options);

    // Follow the command line, and initialize a logger instance which gets and saves the logs
    StdoutLogger::Disable();
    if (global_options.logger == Logger::Stdout) {
        StdoutLogger::Enable();
    } else if (global_options.logger == Logger::LogFile) {
        if (global_options.log_file.has_value()) {
            DEBUG("LogFile logger is enabled");
            LogFileLogger::Init(global_options.log_file.value());
        } else {
            throw exceptions::cli_error("LogFile logger is specified, but log_file "
                                        "is not specified. May be logic bug",
                                        __FILE__, __LINE__);
        }
    } else {
        throw exceptions::cli_error("Unsupported logger: " +
                                      to_string(global_options.logger),
                                    __FILE__, __LINE__);
    }

    // Prepare a fuzzer specified by the command line as it states
    return FuzzerBuilderRegister::Get(global_options.fuzzer)(fuzzer_args, global_options);
}

} // namespace fuzzuf::cli
