/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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

#ifndef FUZZUF_INCLUDE_CLI_MOPT_BUILD_MOPT_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_MOPT_BUILD_MOPT_FROM_ARGS_HPP

#include <memory>
#include <boost/program_options.hpp>

#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"
#include "fuzzuf/algorithms/mopt/mopt_havoc.hpp"
#include "fuzzuf/algorithms/mopt/mopt_state.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"

namespace fuzzuf::cli::fuzzer::mopt {

namespace po = boost::program_options;

struct MOptFuzzerOptions {
    bool forksrv;                           // Optional

    // Default values
    MOptFuzzerOptions() : 
        forksrv(true)
        {}
};

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
    std::cerr << "Help:" << std::endl;
    std::cerr << desc << std::endl;
    exit(1);
}

// Used only for CLI
template <class TFuzzer, class TMOptFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildMOptFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, 
    GlobalFuzzerOptions &global_options
) {
    po::positional_options_description pargs_desc;
    pargs_desc.add("fuzzer", 1);
    pargs_desc.add("pargs", -1);

    MOptFuzzerOptions mopt_options;

    po::options_description fuzzer_desc("MOpt options");
    std::vector<std::string> pargs;
    fuzzer_desc.add_options()
        ("forksrv", 
            po::value<bool>(&mopt_options.forksrv)->default_value(mopt_options.forksrv), 
            "Enable/disable fork server mode. default is true.")
        // If you want to add fuzzer specific options, add options here
        ("pargs", 
            po::value<std::vector<std::string>>(&pargs), 
            "Specify PUT and args for PUT.");

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
        fuzzuf::cli::fuzzer::mopt::usage(fuzzer_args.global_options_description);
    }

    PutArgs put(pargs);
    try {
        put.Check();
    } catch (const exceptions::cli_error &e) {
        std::cerr << "[!] " << e.what() << std::endl;
        std::cerr << "\tat " << e.file << ":" << e.line << std::endl;
        fuzzuf::cli::fuzzer::mopt::usage(fuzzer_args.global_options_description);
    } 

    // Trace level log
    DEBUG("[*] PUT: put = [");
    for (auto v : put.Args()) {
        DEBUG("\t\"%s\",", v.c_str());
    }
    DEBUG("    ]");

    using fuzzuf::algorithm::mopt::option::MOptTag;
    using fuzzuf::algorithm::afl::AFLSetting;
    using fuzzuf::algorithm::afl::option::GetExecTimeout;
    using fuzzuf::algorithm::afl::option::GetMemLimit;

    // Create AFLSetting

    auto setting = std::make_shared<const AFLSetting>(
                        put.Args(),
                        global_options.in_dir,
                        global_options.out_dir,
                        global_options.exec_timelimit_ms.value_or(GetExecTimeout<MOptTag>()),
                        global_options.exec_memlimit.value_or(GetMemLimit<MOptTag>()),
                        mopt_options.forksrv,
                        /* dumb_mode */ false,  // FIXME: add dumb_mode
                        Util::CPUID_BIND_WHICHEVER
                    );

    // NativeLinuxExecutor needs the directory specified by "out_dir" to be already set up
    // so we need to create the directory first, and then initialize Executor
    SetupDirs(setting->out_dir.string());

    using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
    using fuzzuf::cli::ExecutorKind;

    std::shared_ptr<TExecutor> executor;
    switch (global_options.executor) {
    case ExecutorKind::NATIVE: {
        using algorithm::mopt::SharedData;
        // Create NativeLinuxExecutor
        auto nle = std::make_shared<NativeLinuxExecutor>(
                            setting->argv,
                            setting->exec_timelimit_ms,
                            setting->exec_memlimit,
                            setting->forksrv,
                            setting->out_dir / GetDefaultOutfile<MOptTag>(),
                            sizeof(SharedData), // afl_shm_size
                            0 // bb_shm_size
                        );
        executor = std::make_shared<TExecutor>(std::move(nle));
        break;
    }

    default:
        EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
    }

    auto mutop_optimizer = std::unique_ptr<optimizer::Optimizer<u32>>(
                              new algorithm::mopt::havoc::MOptHavocCaseDistrib()
                           );

    // Create MOptState
    using fuzzuf::algorithm::mopt::MOptState;
    auto state = std::make_unique<MOptState>(
                    setting,
                    executor,
                    std::move(mutop_optimizer)
                 );

    return std::unique_ptr<TFuzzer>(
                dynamic_cast<TFuzzer *>(
                    new TMOptFuzzer(std::move(state))
                )
            );
}

} // namespace fuzzuf::cli::fuzzer::mopt

#endif