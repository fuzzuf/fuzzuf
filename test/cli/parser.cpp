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
#define BOOST_TEST_MODULE cli.parser
#define BOOST_TEST_DYN_LINK
#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

#define Argc(argv) (sizeof(argv) / sizeof(char *))

fuzzuf::cli::GlobalFuzzerOptions default_options;  // Default value goes here

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_AllOptions) {
  fuzzuf::cli::GlobalFuzzerOptions options;

#pragma GCC diagnostic ignored "-Wwrite-strings"
  const char *argv[] = {"fuzzuf",
                        "fuzzer",
                        "--in_dir=test-in",
                        "--out_dir=test-out",
                        "--executor=qemu",
                        "--bind_cpuid=1000",
                        "--proxy_path=test-proxy",
                        "--exec_timelimit_ms=123",
                        "--exec_memlimit=456"};
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };
  fuzzuf::cli::FuzzerArgs fuzzer_args =
      fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);

  // Check if fuzzer is captured
  BOOST_CHECK_EQUAL(options.fuzzer, "fuzzer");

  // Check if `options` reflects `argv`
  BOOST_CHECK_EQUAL(options.in_dir, "test-in");
  BOOST_CHECK_EQUAL(options.out_dir, "test-out");
  BOOST_CHECK_EQUAL(options.executor, fuzzuf::cli::ExecutorKind::QEMU);
  BOOST_CHECK_EQUAL(options.cpuid_to_bind, 1000);
  BOOST_CHECK_EQUAL(options.proxy_path.value(), "test-proxy");
  BOOST_CHECK_EQUAL(options.exec_timelimit_ms.value(), 123);
  BOOST_CHECK_EQUAL(options.exec_memlimit.value(), 456);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_DefaultValues) {
  fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
  const char *argv[] = {"fuzzuf", "fuzzer", "--"};
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };
  fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);

  // `*_dir` must be default value since they are not specifed by the commad
  // line
  BOOST_CHECK_EQUAL(options.in_dir, default_options.in_dir);
  BOOST_CHECK_EQUAL(options.out_dir, default_options.out_dir);

  // Check `executor`, `bind_cpuid` and `proxy_path` default value.
  BOOST_CHECK_EQUAL(options.executor, fuzzuf::cli::ExecutorKind::NATIVE);
  BOOST_CHECK_EQUAL(options.cpuid_to_bind, fuzzuf::utils::CPUID_BIND_WHICHEVER);
  BOOST_CHECK_EQUAL(options.proxy_path.value(), "");

  BOOST_CHECK_EQUAL(options.logger, fuzzuf::utils::Logger::Stdout);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_ExecutorKinds) {
  // Check `native` executor.
  {
    fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--executor=native", "--"};
    fuzzuf::cli::GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);

    // Check `executor` and `proxy_path`.
    BOOST_CHECK_EQUAL(options.executor, fuzzuf::cli::ExecutorKind::NATIVE);
    BOOST_CHECK_EQUAL(options.proxy_path.value(), "");
  }

  // Check `qemu` executor.
  {
    fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--executor=qemu",
                          "--proxy_path=test_proxy", "--"};
    fuzzuf::cli::GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);

    // Check `executor` and `proxy_path`.
    BOOST_CHECK_EQUAL(options.executor, fuzzuf::cli::ExecutorKind::QEMU);
    BOOST_CHECK_EQUAL(options.proxy_path.value(), "test_proxy");
  }

  // Check `coresight` executor.
  {
    fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--executor=coresight",
                          "--proxy_path=test_proxy", "--"};
    fuzzuf::cli::GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);

    // Check `executor` and `proxy_path`.
    BOOST_CHECK_EQUAL(options.executor, fuzzuf::cli::ExecutorKind::CORESIGHT);
    BOOST_CHECK_EQUAL(options.proxy_path.value(), "test_proxy");
  }
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_ExecutorKindsFailure) {
  // Supply unknown executor type `foo`.
  {
    fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--executor=foo", "--"};
    fuzzuf::cli::GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };

    // Check if the parser throws expected exception.
    BOOST_CHECK_THROW(fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options),
                      boost::program_options::invalid_option_value);
  }

  // Supply `proxy_path` with `native` executor.
  {
    fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--executor=native",
                          "--proxy_path=test_proxy", "--"};
    fuzzuf::cli::GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };

    // Check if the parser throws expected exception.
    BOOST_CHECK_THROW(fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options),
                      fuzzuf::exceptions::cli_error);
  }

  // `qemu` executor without supplying `proxy_path`.
  {
    fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--executor=qemu", "--"};
    fuzzuf::cli::GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };

    // Check if the parser throws expected exception.
    BOOST_CHECK_THROW(fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options),
                      fuzzuf::exceptions::cli_error);
  }

  // `coresight` executor without supplying `proxy_path`.
  {
    fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--executor=coresight", "--"};
    fuzzuf::cli::GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };

    // Check if the parser throws expected exception.
    BOOST_CHECK_THROW(fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options),
                      fuzzuf::exceptions::cli_error);
  }
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_BindCpuIdFailure) {
  fuzzuf::cli::GlobalFuzzerOptions options;

  const char *argv[] = {"fuzzuf", "fuzzer", "--bind_cpuid=-3", "--"};
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };

  // Check if the parser throws expected exception.
  BOOST_CHECK_THROW(fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options),
                    fuzzuf::exceptions::cli_error);
}


BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_LogFileSpecified) {
  fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
  const char *argv[] = {"fuzzuf", "fuzzer", "--log_file=5rC3kk6PzF5P2sPs.log",
                        "--"};
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };
  fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);

  BOOST_CHECK_EQUAL(options.logger, fuzzuf::utils::Logger::LogFile);

  BOOST_CHECK_EQUAL(options.log_file.value().string(), "5rC3kk6PzF5P2sPs.log");
}

inline void BaseSenario_ParseGlobalFuzzerOptions_WithUnregisteredOption(
    const char test_case_name[], fuzzuf::cli::GlobalArgs &args,
    fuzzuf::cli::GlobalFuzzerOptions &options) {
  UNUSED(test_case_name);

  // Any of exceptions should not be thrown. ParseGlobalOptionsForFuzzer ignores
  // unregistered options while parsing.
  fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_WithUnregisteredOption_Case1) {
  fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
  const char *argv[] = {"fuzzuf", "fuzzer", "--in_dir=in", "--no-such-option"};
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };
  BaseSenario_ParseGlobalFuzzerOptions_WithUnregisteredOption(
      "ParseGlobalFuzzerOptions_WithUnregisteredOption_Case1", args, options);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_WithUnregisteredOption_Case2) {
  fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
  const char *argv[] = {"fuzzuf", "fuzzer", "--in_dir=in", "--no-such-option",
                        "--out_dir=out"};  // Sandwitch unregistered option
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };
  BaseSenario_ParseGlobalFuzzerOptions_WithUnregisteredOption(
      "ParseGlobalFuzzerOptions_WithUnregisteredOption_Case2", args, options);
}

// NOTE:
// もしAFL向けのオプションを追加したら、それの正常動作を確認するテストケースを追加してくださいね
