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
#define UNUSED(x) (void)(x)

GlobalFuzzerOptions default_options; // Default value goes here

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_AllOptions) {
    GlobalFuzzerOptions options;

    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--in_dir=test-in", "--out_dir=test-out", "--exec_timelimit_ms=123", "--exec_memlimit=456"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    FuzzerArgs fuzzer_args = ParseGlobalOptionsForFuzzer(args, options);

    // Check if fuzzer is captured
    BOOST_CHECK_EQUAL(options.fuzzer, "fuzzer");

    // Check if `options` reflects `argv`
    BOOST_CHECK_EQUAL(options.in_dir, "test-in");
    BOOST_CHECK_EQUAL(options.out_dir, "test-out");
    BOOST_CHECK_EQUAL(options.exec_timelimit_ms.value(), 123);
    BOOST_CHECK_EQUAL(options.exec_memlimit.value(), 456);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_InOutDirsAreBlank) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--exec_timelimit_ms=123", "--exec_memlimit=456", "--"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    ParseGlobalOptionsForFuzzer(args, options);

    // `*_dir` must be default value since they are not specifed by the commad line
    BOOST_CHECK_EQUAL(options.in_dir, default_options.in_dir);
    BOOST_CHECK_EQUAL(options.out_dir, default_options.out_dir);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_NoLogFileSpecified) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--"};
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
    const char *argv[] = {"fuzzuf", "fuzzer", "--log_file=5rC3kk6PzF5P2sPs.log", "--"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    ParseGlobalOptionsForFuzzer(args, options);

    BOOST_CHECK_EQUAL(options.logger, Logger::LogFile);

    BOOST_CHECK_EQUAL(options.log_file.value().string(), "5rC3kk6PzF5P2sPs.log");
}

inline void BaseSenario_ParseGlobalFuzzerOptions_WithUnregisteredOption(
    const char test_case_name[], GlobalArgs &args, GlobalFuzzerOptions &options) 
{
    UNUSED(test_case_name);

    // Any of exceptions should not be thrown. ParseGlobalOptionsForFuzzer ignores unregistered options while parsing.
    ParseGlobalOptionsForFuzzer(args, options);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_WithUnregisteredOption_Case1) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--in_dir=in", "--no-such-option"};
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    BaseSenario_ParseGlobalFuzzerOptions_WithUnregisteredOption("ParseGlobalFuzzerOptions_WithUnregisteredOption_Case1", args, options);
}

BOOST_AUTO_TEST_CASE(ParseGlobalFuzzerOptions_WithUnregisteredOption_Case2) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {"fuzzuf", "fuzzer", "--in_dir=in", "--no-such-option", "--out_dir=out"}; // Sandwitch unregistered option
    GlobalArgs args = {
        .argc = Argc(argv),
        .argv = argv,
    };
    BaseSenario_ParseGlobalFuzzerOptions_WithUnregisteredOption("ParseGlobalFuzzerOptions_WithUnregisteredOption_Case2", args, options);
}

BOOST_AUTO_TEST_CASE(BuildAFLByParsingGlobalOptionAndPUT) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {
        "fuzzuf",
        "afl",
        // Global options
        "--in_dir=gS53LCfbAhunlziS", 
        "--forksrv=false",
        // PUT options. 
        // Because NativeLinuxExecutor throws error,
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

BOOST_AUTO_TEST_CASE(BuildAFLByParsingGlobalOptionAndFuzzerOptionAndPUT) {
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    const char *argv[] = {
        "fuzzuf",
        "afl",
        // Global options
        "--in_dir=u4I8Vq8mMTaCE5CH", 
        "--forksrv=false",
        // Fuzzer options
        "--dict_file=" TEST_DICTIONARY_DIR "/test.dict",
        // PUT options. 
        // Because NativeLinuxExecutor throws error,
        // we can't use a random value here.
        "../put_binaries/command_wrapper", // PUT
        "f996ko6rvPgSajvm" // arguments
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

    // Check if global option is captured correctly
    BOOST_CHECK_EQUAL(options.in_dir, "u4I8Vq8mMTaCE5CH");

    auto& state = *fuzzer->state;

    // Check if fuzzer option (dict_file) is captured correctly, and dict file has been loaded
    BOOST_CHECK_EQUAL(state.extras.size(), 3);

    // Check if PUT args are captured correctly
    BOOST_CHECK_EQUAL(state.setting->argv.size(), 2);
    BOOST_CHECK_EQUAL(state.setting->argv[0], "../put_binaries/command_wrapper");
    BOOST_CHECK_EQUAL(state.setting->argv[1], "f996ko6rvPgSajvm");
}

BOOST_AUTO_TEST_CASE(BuildAFLFastByParsingGlobalOptionAndPUT) {
    using AFLFastState = fuzzuf::algorithm::aflfast::AFLFastState;
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    // 本来はschedule用のオプションもテストされるべきだが、CLI側の改修が必要なので一旦放置
    const char *argv[] = {
        "fuzzuf",
        "aflfast",
        // Global options
        "--in_dir=chahz3ea4deRah4o", 
        "--forksrv=false",
        // PUT options. 
        // Because NativeLinuxExecutor throws error,
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

// NOTE: もしAFL向けのオプションを追加したら、それの正常動作を確認するテストケースを追加してくださいね

BOOST_AUTO_TEST_CASE(BuildVUzzerByParsingGlobalOptionAndPUT) {
    using VUzzerState = fuzzuf::algorithm::vuzzer::VUzzerState;
    GlobalFuzzerOptions options;
    #pragma GCC diagnostic ignored "-Wwrite-strings"
    
    const char *argv[] = {
        "fuzzuf",
        "vuzzer",
        // Global options
        "--in_dir=1yGosmSge1Fb4pNA", 
        "--weight=db05iKsZORKkxela",
        "--full_dict=SNqUXXzGJqyE78SC",
        "--unique_dict=lz025YtrYx3hLoYO",
        "--inst_bin=BSAGFocvr8wPERXK",
        "--taint_db=dKiBtlnutZAUczkS",
        "--taint_out=a85cZxCSaxkpewYb",
        "--",
        // PUT options. 
        // Because NativeLinuxExecutor throws error,
        // we can't use a random value here.
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
