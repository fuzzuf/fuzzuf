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
#include "fuzzuf/cli/fuzzer/afl/build_afl_fuzzer_from_args.hpp"
#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/log_file_logger.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/logger/stdout_logger.hpp"

#include <iostream>


int main(int argc, const char *argv[]) {
  try {
    // Prepare a fuzzer specified by the command line as it states
    auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);

    // TODO: Implement signal handler settings
    // It would be nice if a CLI's signal handler can be responsible for calling fuzzer->ReceiveStopSignal() in the 
    // future

    // Now the fuzzing campaign begins
    // TODO: The timeout for the fuzzing campaign has not been implemented.
    // FIXME: fuzzer->ShouldEnd() seems always false when libfuzzer&nezha is used
    while (!fuzzer->ShouldEnd()) {
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
