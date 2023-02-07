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
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"

#include <boost/optional.hpp>
#include <boost/program_options.hpp>
#include <optional>
#include <string>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/check_if_string_is_decimal.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/optparser.hpp"

namespace po = boost::program_options;

namespace fuzzuf::cli {

// Implements >>operator for ExecutorKind to support the class in
// boost::program_options.
std::istream& operator>>(std::istream& in, ExecutorKind& executor) {
  std::string token;
  in >> token;
  if (token == "native")
    executor = ExecutorKind::NATIVE;
  else if (token == "forkserver")
    executor = ExecutorKind::FORKSERVER;
  else if (token == "qemu")
    executor = ExecutorKind::QEMU;
  else if (token == "coresight")
    executor = ExecutorKind::CORESIGHT;
  else
    in.setstate(std::ios_base::failbit);
  return in;
}

FuzzerArgs ParseGlobalOptionsForFuzzer(GlobalArgs& global_args,
                                       GlobalFuzzerOptions& global_options) {
  // Parse a sub-command
  po::positional_options_description subcommand;
  subcommand.add("fuzzer", 1);
  subcommand.add("fargs", -1);

  // Allocate variables to heap since `global_desc` outlives from this function

  // Define global options
  po::options_description global_desc("Global options");
  global_desc.add_options()(
      "fuzzer", po::value<std::string>(&global_options.fuzzer),
      "Specify fuzzer to be used in your fuzzing campaign.")(
      "help", po::bool_switch(&global_options.help), "Produce help message.")(
      "in_dir,i", po::value<std::string>(&global_options.in_dir),
      "Set seed dir. Default is `./seeds`.")(
      "out_dir,o", po::value<std::string>(&global_options.out_dir),
      "Set output dir. Default is `/tmp/fuzzuf-out_dir`.")(
      "executor,e",
      po::value<fuzzuf::cli::ExecutorKind>(&global_options.executor)
          ->default_value(global_options.executor),
      "Specify fuzzing executor. Default is `native`.")(
      "bind_cpuid,b",
      po::value<int>(&global_options.cpuid_to_bind)
          ->default_value(global_options.cpuid_to_bind),
      "Choose a CPU core to bind the PUT process to. Valid values: -2=\"never bind\", -1=\"use any free core\", 0 ~ num_of_cpus-1=(the id of a specific core).")(
      "proxy_path",
      global_options.proxy_path ? po::value<std::string>()->default_value(
                                      global_options.proxy_path->string())
                                : po::value<std::string>()->default_value(""),
      "Specify executor proxy (e.g. `afl-qemu-trace`) path.")(
      "exec_timelimit_ms,t",
      global_options.exec_timelimit_ms
          ? po::value<u32>()->default_value(*global_options.exec_timelimit_ms)
          : po::value<u32>(),
      "Limit execution time of PUT. Unit is milli-seconds.")(
      "exec_memlimit,m",
      global_options.exec_memlimit
          ? po::value<u32>()->default_value(*global_options.exec_memlimit)
          : po::value<u32>(),
      "Limit memory usage for PUT execution.")(
      "log_file",
      global_options.log_file ? po::value<std::string>()->default_value(
                                    global_options.log_file->string())
                              : po::value<std::string>()->default_value(""),
      "Enable LogFile logger and set the log file path for LogFile logger");

  // Dummy options to parse global options but not PUT options
  // NOTE: PUT options are parsed at fuzzer builder
  po::options_description fargs("Fuzzer options");
  fargs.add_options()(
      "fargs", po::value<std::vector<std::string>>(),
      "Specify Fuzzer options and PUT args.")  // pargs is not captured while
                                               // parsing global options
      ;

  // Obtain global fuzzing campaign settings from the command line
  po::variables_map vm;
  po::store(po::command_line_parser(global_args.argc, global_args.argv)
                .options(global_desc.add(fargs))
                .positional(subcommand)
                .allow_unregistered()
                .run(),
            vm);
  po::notify(vm);

  // Show a usage and exit because none of fuzzers are specified
  // TODO: Provide better help message
  if (vm.count("fuzzer") == 0) {
    if (global_options.help) {
      std::cout << "fuzzuf" << std::endl;
      std::cout << global_desc << std::endl;
      exit(0);
    } else {
      throw exceptions::cli_error(
          "`fuzzer` is not specified in command line. Run with `--help` to "
          "check usage",
          __FILE__, __LINE__);
    }
  }
  DEBUG("[*] global_options.fuzzer = %s", global_options.fuzzer.c_str());

  // Store values to `global_options` manually

  using fuzzuf::cli::ExecutorKind;
  auto exec_kind = vm["executor"].as<ExecutorKind>();
  auto proxy_path = vm["proxy_path"].as<std::string>();
  bool takes_proxy_path = !(exec_kind == ExecutorKind::NATIVE) &&
                          !(exec_kind == ExecutorKind::FORKSERVER);
  if (!takes_proxy_path && !proxy_path.empty()) {
    // ExecutorKind::NATIVE must not take proxy_path.
    throw exceptions::cli_error(
        "`--proxy_path` is specified, but never used by `native` executor",
        __FILE__, __LINE__);
  } else if (takes_proxy_path && proxy_path.empty()) {
    // Other ExecutorKind must take proxy_path.
    throw exceptions::cli_error("`--proxy_path` is not specified", __FILE__,
                                __LINE__);
  } else {
    global_options.proxy_path = fs::path(std::move(proxy_path));
  }

  if (!utils::IsValidCpuId(global_options.cpuid_to_bind)) {
    throw exceptions::cli_error(
        "Invalid value is fed to `-b,--bind_cpuid`. Valid values: -2=\"never bind\", -1=\"use any free core\", 0 ~ num_of_cpus-1=(the id of a specific core)",
        __FILE__, __LINE__);
  }

  // since type T = { std::optional, fs::path, Logger (enum) }, is not cpmatible
  // with po::value<T>()
  if (vm.count("exec_timelimit_ms")) {
    global_options.exec_timelimit_ms = vm["exec_timelimit_ms"].as<u32>();
  }
  if (vm.count("exec_memlimit")) {
    global_options.exec_memlimit = vm["exec_memlimit"].as<u32>();
  }
  auto log_file = vm["log_file"].as<std::string>();
  if (!log_file.empty()) {
    global_options.log_file = fs::path(std::move(log_file));
    global_options.logger = fuzzuf::utils::Logger::LogFile;
  }

  return FuzzerArgs{.argc = global_args.argc,
                    .argv = global_args.argv,
                    .global_options_description = global_desc};
}

}  // namespace fuzzuf::cli
