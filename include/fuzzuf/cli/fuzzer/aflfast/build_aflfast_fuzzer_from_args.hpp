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

#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_option.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_setting.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"

// Used only for CLI
template <class TFuzzer, class TAFLFuzzer>
std::unique_ptr<TFuzzer> BuildAFLFastFuzzerFromArgs(FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
    enum optionIndex {
        // Blank
    };

    const option::Descriptor usage[] = {
        // Blank
        {0, 0, 0, 0, 0, 0}
    };

    option::Stats  stats(usage, fuzzer_args.argc, fuzzer_args.argv);
    option::Option options[stats.options_max], buffer[stats.buffer_max];
    option::Parser parse(usage, fuzzer_args.argc, fuzzer_args.argv, options, buffer);

    if (parse.error()) {
        throw exceptions::cli_error(Util::StrPrintf("Failed to parse AFLFast command line"), __FILE__, __LINE__);
    }

    // Add handlers for local options here

    PutArgs put = {
        .argc = parse.nonOptionsCount(),
        .argv = parse.nonOptions()
    };

    if (put.argc == 0) {
        throw exceptions::cli_error(Util::StrPrintf("Command line of PUT is not specified"), __FILE__, __LINE__);
    }

    // Trace level log
    DEBUG("[*] PUT: put = [");
    for (auto v : put.Args()) {
        DEBUG("\t\"%s\",", v.c_str());
    }
    DEBUG("    ]");

    using fuzzuf::algorithm::aflfast::AFLFastSetting;
    using fuzzuf::algorithm::aflfast::option::AFLFastTag;
    using fuzzuf::algorithm::afl::option::GetExecTimeout;
    using fuzzuf::algorithm::afl::option::GetMemLimit;
    using fuzzuf::algorithm::aflfast::option::FAST;

    // Create AFLFastSetting

    auto setting = std::make_shared<const AFLFastSetting>(
                        put.Args(),
                        global_options.in_dir,
                        global_options.out_dir,
                        global_options.exec_timelimit_ms.value_or(GetExecTimeout<AFLFastTag>()),
                        global_options.exec_memlimit.value_or(GetMemLimit<AFLFastTag>()),
                        /* forksrv */   true, // FIXME: support non fork server mode also
                        /* dumb_mode */ false,  // FIXME: add dumb_mode
                        NativeLinuxExecutor::CPUID_BIND_WHICHEVER,
                        FAST
                    );

    // NativeLinuxExecutor needs the directory specified by "out_dir" to be already set up
    // so we need to create the directory first, and then initialize Executor
    SetupDirs(setting->out_dir.string());

    using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
    using fuzzuf::algorithm::afl::option::GetMapSize;

    // Create NativeLinuxExecutor
    // TODO: support more types of executors

    auto executor = std::make_shared<NativeLinuxExecutor>(
                        setting->argv,
                        setting->exec_timelimit_ms,
                        setting->exec_memlimit,
                        setting->forksrv,
                        setting->out_dir / GetDefaultOutfile<AFLFastTag>(),
                        GetMapSize<AFLFastTag>(), // afl_shm_size
                                           0, //  bb_shm_size
                        setting->cpuid_to_bind
                    );

    // Create AFLFastState
    using fuzzuf::algorithm::aflfast::AFLFastState;
    auto state = std::make_unique<AFLFastState>(setting, executor);

    return std::unique_ptr<TFuzzer>(
                dynamic_cast<TFuzzer *>(
                    new TAFLFuzzer(std::move(state))
                )
            );
}
