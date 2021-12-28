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
#define BOOST_TEST_MODULE cli.parser
#define BOOST_TEST_DYN_LINK
#include <array>
#include <iostream>
#include <boost/test/unit_test.hpp>

#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/cli/stub/afl_fuzzer_stub.hpp"
#include "fuzzuf/cli/stub/vuzzer_stub.hpp"
#include "fuzzuf/cli/fuzzer/afl/build_afl_fuzzer_from_args.hpp"
#include "fuzzuf/cli/fuzzer/aflfast/build_aflfast_fuzzer_from_args.hpp"
#include "fuzzuf/cli/fuzzer/vuzzer/build_vuzzer_from_args.hpp"

#define Argc(argv) (sizeof(argv) / sizeof(char *))

GlobalFuzzerOptions default_options; // Default value goes here

BOOST_AUTO_TEST_CASE(TheLeanMeanCPPOptPerser_CheckSpec) {
    GlobalFuzzerOptions options;
    options.fuzzer = "xyz";

    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"--in_dir=test-in", "--out_dir=test-out", "--exec_timelimit_ms=123", "--exec_memlimit=456", "--", "--some-afl-option=true"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    FuzzerArgs fuzzer_args = ParseGlobalOptionsForFuzzer(args, options);

    DEBUG("[*] &argv[5] = %p", &argv[5]);
    DEBUG("[*] fuzzer_args.argv = %p", fuzzer_args.argv);

    BOOST_CHECK_EQUAL(fuzzer_args.argc, 1);
    BOOST_CHECK_EQUAL(fuzzer_args.argv, &argv[5]);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_AllOptions) {
    GlobalFuzzerOptions options;
    options.fuzzer = "xyz";

    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"--in_dir=test-in", "--out_dir=test-out", "--exec_timelimit_ms=123", "--exec_memlimit=456", "--", "--some-afl-option=true"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    FuzzerArgs fuzzer_args = ParseGlobalOptionsForFuzzer(args, options);

    // Check if `options` reflects `argv`
    BOOST_CHECK_EQUAL(options.in_dir, "test-in");
    BOOST_CHECK_EQUAL(options.out_dir, "test-out");
    BOOST_CHECK_EQUAL(options.exec_timelimit_ms.value(), 123);
    BOOST_CHECK_EQUAL(options.exec_memlimit.value(), 456);

    // Check if `fuzzer` is not affected
    BOOST_CHECK_EQUAL(options.fuzzer, "xyz");

    // Check if FuzzerArgs contains command line options for a fuzzer
    BOOST_CHECK_EQUAL(fuzzer_args.argc, 1);
    BOOST_CHECK_EQUAL(fuzzer_args.argv[0], "--some-afl-option=true");
}

BOOST_AUTO_TEST_CASE(ParseAFLFuzzerOptions_AllOptions){
    GlobalFuzzerOptions options;
    options.fuzzer = "afl";

    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"--in_dir=test-in", "--out_dir=test-out", "--exec_timelimit_ms=123", "--exec_memlimit=456", "--", "--dict_file=aaa.dict"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    FuzzerArgs fuzzer_args = ParseGlobalOptionsForFuzzer(args, options);

    // Check if `options` reflects `argv`
    BOOST_CHECK_EQUAL(options.in_dir, "test-in");
    BOOST_CHECK_EQUAL(options.out_dir, "test-out");
    BOOST_CHECK_EQUAL(options.exec_timelimit_ms.value(), 123);
    BOOST_CHECK_EQUAL(options.exec_memlimit.value(), 456);

    // Check if `fuzzer` is not affected
    BOOST_CHECK_EQUAL(options.fuzzer, "afl");

    // Check if FuzzerArgs contains command line options for a fuzzer
    BOOST_CHECK_EQUAL(fuzzer_args.argc, 1);
    BOOST_CHECK_EQUAL(fuzzer_args.argv[0], "--dict_file=aaa.dict");
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_DirsAreBlank) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"--exec_timelimit_ms=123", "--exec_memlimit=456", "--"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    ParseGlobalOptionsForFuzzer(args, options);

    // `*_dir` must be default value since they are not specifed by the commad line
    BOOST_CHECK_EQUAL(options.in_dir, default_options.in_dir);
    BOOST_CHECK_EQUAL(options.out_dir, default_options.out_dir);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_NoLogOption) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"--"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    ParseGlobalOptionsForFuzzer(args, options);

    BOOST_CHECK_EQUAL(options.logger, Logger::Stdout);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_LogFileSpecified) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"--log_file=5rC3kk6PzF5P2sPs.log", "--"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    ParseGlobalOptionsForFuzzer(args, options);

    BOOST_CHECK_EQUAL(options.logger, Logger::LogFile);

    BOOST_CHECK_EQUAL(options.log_file.value().string(), "5rC3kk6PzF5P2sPs.log");
}

inline void BaseSenario_ParseGlobalFuzzerOptions_WithWrongOption(
    const char test_case_name[], GlobalArgs &args, GlobalFuzzerOptions &options) {
    try {
        ParseGlobalOptionsForFuzzer(args, options);

        BOOST_ASSERT_MSG(false, "cli_error should be thrown in this test case");
    } catch (const exceptions::cli_error &e) {
        // Exception has been thrown. This test case passed
        const char expected_cli_error_message[] = "Unknown option or missing handler for option";
        BOOST_CHECK_EQUAL(strncmp(e.what(), expected_cli_error_message, strlen(expected_cli_error_message)), 0);
        DEBUG("[*] Caught cli_error as expected: %s: %s at %s:%d", test_case_name, e.what(), e.file, e.line);
    }
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_WithWrongOption_Case1) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"--in_dir=in", "--no-such-option"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    BaseSenario_ParseGlobalFuzzerOptions_WithWrongOption("ParseGlobalFuzzerOptions_WithWrongOption_Case1", args, options);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_WithWrongOption_Case2) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"--in_dir=in", "--no-such-option", "--out_dir=out"}; // Sandwitch
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    BaseSenario_ParseGlobalFuzzerOptions_WithWrongOption("ParseGlobalFuzzerOptions_WithWrongOption_Case2", args, options);
}

BOOST_AUTO_TEST_CASE(BuildAFLByParsingGlobalOptionAndPUT) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {
        "--in_dir=gS53LCfbAhunlziS", // Global options
        // PUT. Because NativeLinuxExecutor throws error,
        // we can't use a random value here.
        "../put_binaries/command_wrapper", // PUT
        "Jpx1kB6oh8N9wUe0" // arguments
        };
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };

    using AFLState = fuzzuf::algorithm::afl::AFLState;

    // Parse global options and PUT, and build fuzzer
    auto fuzzer_args = ParseGlobalOptionsForFuzzer(args, options);
    auto fuzzer = BuildAFLFuzzerFromArgs<AFLFuzzerStub<AFLState>, AFLFuzzerStub<AFLState>>(
            fuzzer_args, options
        );

    BOOST_CHECK_EQUAL(options.in_dir, "gS53LCfbAhunlziS");

    auto& state = *fuzzer->state;
    BOOST_CHECK_EQUAL(state.setting->argv.size(), 2);
    BOOST_CHECK_EQUAL(state.setting->argv[0], "../put_binaries/command_wrapper");
    BOOST_CHECK_EQUAL(state.setting->argv[1], "Jpx1kB6oh8N9wUe0");
}

BOOST_AUTO_TEST_CASE(BuildAFLFastByParsingGlobalOptionAndPUT) {
    using AFLFastState = fuzzuf::algorithm::aflfast::AFLFastState;
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    // 本来はschedule用のオプションもテストされるべきだが、CLI側の改修が必要なので一旦放置
    const char *argv[] = {
        "--in_dir=chahz3ea4deRah4o", // Global options
        // PUT. Because NativeLinuxExecutor throws error,
        // we can't use a random value here.
        "../put_binaries/command_wrapper", // PUT
        "oung6UgoQue1eiYu" // arguments
        };
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };

    // Parse global options and PUT, and build fuzzer
    auto fuzzer_args = ParseGlobalOptionsForFuzzer(args, options);
    auto fuzzer = BuildAFLFastFuzzerFromArgs<AFLFuzzerStub<AFLFastState>, AFLFuzzerStub<AFLFastState>>(
            fuzzer_args, options
        );

    BOOST_CHECK_EQUAL(options.in_dir, "chahz3ea4deRah4o");

    auto& state = *fuzzer->state;
    BOOST_CHECK_EQUAL(state.setting->argv.size(), 2);
    BOOST_CHECK_EQUAL(state.setting->argv[0], "../put_binaries/command_wrapper");
    BOOST_CHECK_EQUAL(state.setting->argv[1], "oung6UgoQue1eiYu");
}

// もしAFL向けのオプションを追加したら、それの正常動作を確認するテストケースを追加してくださいね
BOOST_AUTO_TEST_CASE(BuildVUzzerByParsingGlobalOptionAndPUT) {
    using VUzzerState = fuzzuf::algorithm::vuzzer::VUzzerState;
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    
    const char *argv[] = {
        "--in_dir=1yGosmSge1Fb4pNA", // Global options
        // PUT. Because NativeLinuxExecutor throws error,
        // we can't use a random value here.
        "--",
        "--weight=db05iKsZORKkxela",
        "--full_dict=SNqUXXzGJqyE78SC",
        "--unique_dict=lz025YtrYx3hLoYO",
        "--inst_bin=BSAGFocvr8wPERXK",
        "--taint_db=dKiBtlnutZAUczkS",
        "--taint_out=a85cZxCSaxkpewYb",
        "--",
        "../put_binaries/command_wrapper", // PUT
        "HQ5lspLelPJPEC35" // arguments
        };
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };

    // Parse global options and PUT, and build fuzzer
    auto fuzzer_args = ParseGlobalOptionsForFuzzer(args, options);
    auto fuzzer = BuildVUzzerFromArgs<VUzzerStub<VUzzerState>, VUzzerStub<VUzzerState>>(
            fuzzer_args, options
        );

    BOOST_CHECK_EQUAL(options.in_dir, "1yGosmSge1Fb4pNA");

    auto& state = *fuzzer->state;

    BOOST_CHECK_EQUAL(state.setting->path_to_weight_file, "db05iKsZORKkxela");
    BOOST_CHECK_EQUAL(state.setting->path_to_full_dict, "SNqUXXzGJqyE78SC");
    BOOST_CHECK_EQUAL(state.setting->path_to_unique_dict, "lz025YtrYx3hLoYO");
    BOOST_CHECK_EQUAL(state.setting->path_to_inst_bin, "BSAGFocvr8wPERXK");
    BOOST_CHECK_EQUAL(state.setting->path_to_taint_db, "dKiBtlnutZAUczkS");
    BOOST_CHECK_EQUAL(state.setting->path_to_taint_file, "a85cZxCSaxkpewYb");

    BOOST_CHECK_EQUAL(state.setting->argv.size(), 2);
    BOOST_CHECK_EQUAL(state.setting->argv[0], fs::absolute("../put_binaries/command_wrapper").native()); // VUzzer converts PUTs path to abs path.
    BOOST_CHECK_EQUAL(state.setting->argv[1], "HQ5lspLelPJPEC35");
}
