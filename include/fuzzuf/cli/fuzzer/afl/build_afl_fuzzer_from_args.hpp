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
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_setting.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/executor/qemu_executor.hpp"
#ifdef __aarch64__
#include "fuzzuf/executor/coresight_executor.hpp"
#endif
#include <boost/program_options.hpp>

namespace po = boost::program_options;

struct AFLFuzzerOptions {
    bool forksrv;                           // Optional
    std::string dict_file;                  // Optional
    bool frida_mode;                        // Optional

    // Default values
    AFLFuzzerOptions() : 
        forksrv(true),
        dict_file(""),
        frida_mode(false)
        {};
};

namespace fuzzuf::cli::fuzzer::afl {

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
    std::cout << "Help:" << std::endl;
    std::cout << desc << std::endl;
    exit(1);
}

}

// Used only for CLI
template <class TFuzzer, class TAFLFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildAFLFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, 
    GlobalFuzzerOptions &global_options
) {
    po::positional_options_description pargs_desc;
    pargs_desc.add("fuzzer", 1);
    pargs_desc.add("pargs", -1);

    AFLFuzzerOptions afl_options;

    po::options_description fuzzer_desc("AFL options");
    std::vector<std::string> pargs;
    fuzzer_desc.add_options()
        ("forksrv", 
            po::value<bool>(&afl_options.forksrv)->default_value(afl_options.forksrv), 
            "Enable/disable fork server mode. default is true.")
        ("dict_file", 
            po::value<std::string>(&afl_options.dict_file), 
            "Load additional dictionary file.")
        ("pargs", 
            po::value<std::vector<std::string>>(&pargs), 
            "Specify PUT and args for PUT.")
        ("frida",
            po::value<bool>(&afl_options.frida_mode)->default_value(afl_options.frida_mode),
            "Enable/disable frida mode. Default to false.")
    ;

    po::variables_map vm;
    po::store(
        po::command_line_parser(fuzzer_args.argc, fuzzer_args.argv)
            .options(fuzzer_args.global_options_description.add(fuzzer_desc))
            .positional(pargs_desc)
            .run(), 
        vm
        );
    po::notify(vm);

    if (global_options.help) {
        fuzzuf::cli::fuzzer::afl::usage(fuzzer_args.global_options_description);
    }

    if (afl_options.frida_mode) {
        // One of executor classes will handle frida mode later
        setenv("FUZZUF_FRIDA_MODE", "1", 1);
    }

    PutArgs put(pargs);
    try {
        put.Check();
    } catch (const exceptions::cli_error &e) {
        std::cerr << "[!] " << e.what() << std::endl;
        std::cerr << "\tat " << e.file << ":" << e.line << std::endl;
        fuzzuf::cli::fuzzer::afl::usage(fuzzer_args.global_options_description);
    } 

    // Trace level log
    DEBUG("[*] PUT: put = [");
    for (auto v : put.Args()) {
        DEBUG("\t\"%s\",", v.c_str());
    }
    DEBUG("    ]");

    using fuzzuf::algorithm::afl::AFLSetting;
    using fuzzuf::algorithm::afl::option::AFLTag;
    using fuzzuf::algorithm::afl::option::GetExecTimeout;
    using fuzzuf::algorithm::afl::option::GetMemLimit;

    // Create AFLSetting

    auto setting = std::make_shared<const AFLSetting>(
                        put.Args(),
                        global_options.in_dir,
                        global_options.out_dir,
                        global_options.exec_timelimit_ms.value_or(GetExecTimeout<AFLTag>()),
                        global_options.exec_memlimit.value_or(GetMemLimit<AFLTag>()),
                        afl_options.forksrv,
                        /* dumb_mode */ false,  // FIXME: add dumb_mode
                        Util::CPUID_BIND_WHICHEVER
                    );

    // NativeLinuxExecutor needs the directory specified by "out_dir" to be already set up
    // so we need to create the directory first, and then initialize Executor
    SetupDirs(setting->out_dir.string());

    using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
    using fuzzuf::algorithm::afl::option::GetMapSize;
    using fuzzuf::cli::ExecutorKind;

    std::shared_ptr<TExecutor> executor;
    switch (global_options.executor) {
    case ExecutorKind::NATIVE: {
        auto nle = std::make_shared<NativeLinuxExecutor>(
                            setting->argv,
                            setting->exec_timelimit_ms,
                            setting->exec_memlimit,
                            setting->forksrv,
                            setting->out_dir / GetDefaultOutfile<AFLTag>(),
                            GetMapSize<AFLTag>(), // afl_shm_size
                            0 // bb_shm_size
                        );
        executor = std::make_shared<TExecutor>(std::move(nle));
        break;
    }

    case ExecutorKind::QEMU: {
        // NOTE: Assuming GetMapSize<AFLTag>() == QEMUExecutor::QEMU_SHM_SIZE
        auto qe = std::make_shared<QEMUExecutor>(
                            global_options.proxy_path.value(),
                            setting->argv,
                            setting->exec_timelimit_ms,
                            setting->exec_memlimit,
                            setting->forksrv,
                            setting->out_dir / GetDefaultOutfile<AFLTag>()
                        );
        executor = std::make_shared<TExecutor>(std::move(qe));
        break;
    }

#ifdef __aarch64__
    case ExecutorKind::CORESIGHT: {
        auto cse = std::make_shared<CoreSightExecutor>(
                            global_options.proxy_path.value(),
                            setting->argv,
                            setting->exec_timelimit_ms,
                            setting->exec_memlimit,
                            setting->forksrv,
                            setting->out_dir / GetDefaultOutfile<AFLTag>(),
                            GetMapSize<AFLTag>() // afl_shm_size
                        );
        executor = std::make_shared<TExecutor>(std::move(cse));
        break;
    }
#endif

    default:
        EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
    }

    // Create AFLState
    using fuzzuf::algorithm::afl::AFLState;
    auto state = std::make_unique<AFLState>(setting, executor);

    // Load dictionary
    if(afl_options.dict_file != ""){
        using fuzzuf::algorithm::afl::dictionary::AFLDictData;

        const std::function<void( std::string&& )> f = [](std::string s){
            ERROR("Dictionary error: %s", s.c_str());     
        };

        fuzzuf::algorithm::afl::dictionary::load(afl_options.dict_file, state->extras, false, f);
    }

    return std::unique_ptr<TFuzzer>(
                dynamic_cast<TFuzzer *>(
                    new TAFLFuzzer(std::move(state))
                )
            );
}
