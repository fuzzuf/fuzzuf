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
#include "fuzzuf/cli/fuzzer_builder_register.hpp"
#include "fuzzuf/cli/fuzzer/afl/build_afl_fuzzer_from_args.hpp"
#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/log_file_logger.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/logger/stdout_logger.hpp"

#include <iostream>

void usage(const char *argv_0) {
  std::cerr << "Example usage:" << std::endl;
  std::cerr << "\t" << argv_0
            << " afl --in_dir=test/put_binaries/libjpeg/seeds -- "
               "test/put_binaries/libjpeg/libjpeg_turbo_fuzzer @@"
            << std::endl;
  exit(1);
}

int main(int argc, const char *argv[]) {
  try {
    // Explicitly enable logging to stdout as Logger does not get confirmed before parsing command line options
    StdoutLogger::Enable();

    // Show a usage and exit because none of fuzzers are specified
    if (argc < 2) {
      usage(argv[0]);
    }

    GlobalFuzzerOptions global_options;

    // Parse a sub-command in a messy way as it does not expect one other than a fuzzer
    global_options.fuzzer = argv[1];

    // Obtain overall fuzzing campaign settings from the command line
    // NOTE: Beware that it skips argv[0] and a sub-command
    GlobalArgs global_args = {.argc = argc - 2, .argv = &argv[2]};
    FuzzerArgs fuzzer_args =
        ParseGlobalOptionsForFuzzer(global_args, /* &mut */ global_options);

    if (global_options.help) {
      // help inside ParseGlobalOptionsForFuzzer()
      // Exit directly because fuzzuf already showed the message
      return 0;
    }

    // Follow the command line, and initialize a logger instance which gets and saves the logs
    StdoutLogger::Disable();
    if (global_options.logger == Logger::Stdout) {
      StdoutLogger::Enable();
    } else if (global_options.logger == Logger::LogFile) {
      if (global_options.log_file.has_value()) {
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
    auto fuzzer = FuzzerBuilderRegister::Get(global_options.fuzzer)(
        fuzzer_args, global_options);

    // TODO: Implement signal handler settings
    // It would be nice if a CLI's signal handler can be responsible for calling fuzzer->ReceiveStopSignal() in the 
    // future

    // Now the fuzzing campaign begins
    // TODO: The timeout for the fuzzing campaign has not been implemented.
    // `while (true)` should be replaced when appropriate
    while (true) {
      fuzzer->OneLoop();
      // Call hooks per OneLoop, if necessary
    }
  } catch (const exceptions::fuzzuf_runtime_error &e) {
    // CLI does error handling as the topmost module
    std::cerr << "[!] " << e.what() << std::endl;
    std::cerr << "\tat " << e.file << ":" << e.line << std::endl;

    return -1; // Use exit code to indicate that the process has failed with an error
  } catch (const exceptions::fuzzuf_logic_error &e) {
    // CLI does error handling as the topmost module
    std::cerr << "[!] " << e.what() << std::endl;
    std::cerr << "\tat " << e.file << ":" << e.line << std::endl;

    return -1; // Use exit code to indicate that the process has failed with an error
  } catch (const std::exception &e) {
    // CLI does error handling as the topmost module
    std::cerr << "[!] " << e.what() << std::endl;

    return -1; // Use exit code to indicate that the process has failed with an error
  }

  return 0;
}
