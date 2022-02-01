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
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/utils/check_if_string_is_decimal.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include <string>

#include <optional>
#include <string>
#include <boost/program_options.hpp>
#include <boost/optional.hpp>
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/exceptions.hpp"

namespace po = boost::program_options;

FuzzerArgs ParseGlobalOptionsForFuzzer(GlobalArgs &global_args, GlobalFuzzerOptions &global_options) {
    // Parse a sub-command
    po::positional_options_description subcommand;
    subcommand.add("fuzzer", 1);
    subcommand.add("fargs", -1);

    // Allocate variables to heap since `global_desc` outlives from this function
    auto log_file = new std::string();
    auto exec_timelimit_ms = new boost::optional<u32>();
    auto exec_memlimit = new boost::optional<u64>();

    // Define global options
    po::options_description global_desc("Global options");
    global_desc.add_options()
        ("fuzzer", 
            po::value<std::string>(&global_options.fuzzer), 
            "Specify fuzzer to be used in your fuzzing campaign.")
        ("help", 
            po::bool_switch(&global_options.help), 
            "Produce help message.")
        ("in_dir,i", 
            po::value<std::string>(&global_options.in_dir), 
            "Set seed dir. Default is `./seeds`.")
        ("out_dir,o", 
            po::value<std::string>(&global_options.out_dir), 
            "Set output dir. Default is `/tmp/fuzzuf-out_dir`.")
        ("exec_timelimit_ms", 
            po::value<boost::optional<u32>>(exec_timelimit_ms),
            "Limit execution time of PUT. Unit is milli-seconds.")
        ("exec_memlimit", 
            po::value<boost::optional<u64>>(exec_memlimit),
            "Limit memory usage for PUT execution.")
        ("log_file", 
            po::value<std::string>(log_file), 
            "Enable LogFile logger and set the log file path for LogFile logger")
    ;

    // Dummy options to parse global options but not PUT options
    // NOTE: PUT options are parsed at fuzzer builder
    po::options_description fargs("Fuzzer options");
    fargs.add_options()
      ("fargs", po::value<std::vector<std::string>>(), "Specify Fuzzer options and PUT args.") // pargs is not captured while parsing global options
    ;

    // Obtain global fuzzing campaign settings from the command line
    po::variables_map vm;
    po::store(
        po::command_line_parser(global_args.argc, global_args.argv)
            .options(global_desc.add(fargs)).positional(subcommand).allow_unregistered().run(),
        vm
        );
    po::notify(vm);

    // Show a usage and exit because none of fuzzers are specified
    // TODO: Provide better help message
    if (vm.count("fuzzer") == 0) {
        if (global_options.help) {
            std::cout << "fuzzuf" << std::endl;
            std::cout << global_desc << std::endl;
            exit(0);
        } else {
            throw exceptions::cli_error("`fuzzer` is not specified in command line. Run with `--help` to check usage", __FILE__, __LINE__);
        }
    }
    DEBUG("[*] global_options.fuzzer = %s", global_options.fuzzer.c_str());

    // Store values to `global_options` manually 
    // since type T = { std::optional, fs::path, Logger (enum) }, is not cpmatible with po::value<T>()
    if (*exec_timelimit_ms) {
        global_options.exec_timelimit_ms = exec_timelimit_ms->value();
    }
    if (*exec_memlimit) {
        global_options.exec_memlimit = exec_memlimit->value();
    }
    if (log_file->length() > 0) {
        global_options.log_file = fs::path(*log_file);
        global_options.logger = Logger::LogFile;
    }

    return FuzzerArgs {
        .argc = global_args.argc,
        .argv = global_args.argv,
        .global_options_description = global_desc
    };
}
