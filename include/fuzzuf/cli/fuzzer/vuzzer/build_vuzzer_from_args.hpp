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
/**
 * @file BuildVUzzerFromArgs.hpp
 * @brief Build CLI options for VUzzer
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_CLI_VUZZER_BUILD_VUZZER_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_VUZZER_BUILD_VUZZER_FROM_ARGS_HPP

#include "config.h"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_setting.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_state.hpp"
#include "fuzzuf/executor/pintool_executor.hpp"
#include "fuzzuf/executor/polytracker_executor.hpp"

using fuzzuf::algorithm::vuzzer::VUzzer;

struct VUzzerOptions {
    std::string full_dict;                  // Optional
    std::string unique_dict;                // Optional
    std::string weight;                     // Optional
    std::string inst_bin;                   // Optional
    std::string taint_db;                   // Optional
    std::string taint_out;                  // Optional

    // Default values
    VUzzerOptions() : 
        full_dict("./full.dict"), 
        unique_dict("./unique.dict"), 
        weight("./weight"), 
        inst_bin("./instrumented.bin"), 
        taint_db("/mnt/polytracker/polytracker.db"),
        taint_out("/tmp/taint.out")
        {};
};

// Used only for CLI
template <class TFuzzer, class TVUzzer>
std::unique_ptr<TFuzzer> BuildVUzzerFromArgs(FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
    VUzzerOptions vuzzer_options;

    enum optionIndex {
        FullDict,
        UniqueDict,
        Weight,
        InstBin,
        TaintDB,
        TaintOut
    };

    const option::Descriptor usage[] = {
        {optionIndex::FullDict, 0, "", "full_dict", option::Arg::Optional, "    --full_dict FULL_DICT \tSet path to \"full dictionary\". Default is `./full.dict`." },
        {optionIndex::UniqueDict, 0, "", "unique_dict", option::Arg::Optional, "    --unique_dict UNIQUE_DICT \tSet path to \"unique dictionary\". Default is `./unique.dict`." },
        {optionIndex::Weight, 0, "", "weight", option::Arg::Optional, "    --weight WEIGHT \tSet path to \"weight file\". Default is `./weight`." },
        {optionIndex::InstBin, 0, "", "inst_bin", option::Arg::Optional, "    --inst_bin INST_BIN \tSet path to instrumented binary. Default is `./instrumented.bin`." },
        {optionIndex::TaintDB, 0, "", "taint_db", option::Arg::Optional, "    --taint_db TAINT_DB \tSet path to taint db. Default is `/mnt/polytracker/polytracker.db`." },
        {optionIndex::TaintOut, 0, "", "taint_out", option::Arg::Optional, "    --taint_out TAINT_OUT \tSet path to output for taint analysis. Default is `/tmp/taint.out`." },
        {0, 0, 0, 0, 0, 0}
    };

    option::Stats  stats(usage, fuzzer_args.argc, fuzzer_args.argv);
    option::Option options[stats.options_max], buffer[stats.buffer_max];
    option::Parser parse(usage, fuzzer_args.argc, fuzzer_args.argv, options, buffer);

    if (parse.error()) {
        throw exceptions::cli_error(Util::StrPrintf("Failed to parse VUzzer command line"), __FILE__, __LINE__);
    }

    for (int i = 0; i < parse.optionsCount(); ++i) {
        option::Option& opt = buffer[i];
    
        switch(opt.index()) {
            case optionIndex::FullDict: {
                CheckIfOptionHasValue(opt);
                vuzzer_options.full_dict = opt.arg;
                break;
            }
            case optionIndex::UniqueDict: {
                CheckIfOptionHasValue(opt);
                vuzzer_options.unique_dict = opt.arg;
                break;
            }            
            case optionIndex::Weight: {
                CheckIfOptionHasValue(opt);
                vuzzer_options.weight = opt.arg;
                break;
            }
            case optionIndex::InstBin: {
                CheckIfOptionHasValue(opt);
                vuzzer_options.inst_bin = opt.arg;
                break;
            }
            case optionIndex::TaintDB: {
                CheckIfOptionHasValue(opt);
                vuzzer_options.taint_db = opt.arg;
                break;
            }
            case optionIndex::TaintOut: {
                CheckIfOptionHasValue(opt);
                vuzzer_options.taint_out = opt.arg;
                break;
            }            
            default: {
                throw exceptions::cli_error(
                    Util::StrPrintf("Unknown option or missing handler for option \"%s\"", opt.name),
                    __FILE__, __LINE__);
            }
        }
    }

    PutArgs put = {
        .argc = parse.nonOptionsCount(),
        .argv = parse.nonOptions()
    };

    if (put.argc == 0) {
        throw exceptions::cli_error(Util::StrPrintf("Command line of PUT is not specified"), __FILE__, __LINE__);
    }

    std::vector<std::string> args = put.Args();
    DEBUG("[*] PUT: put = [");
    for (auto v : args) {
        DEBUG("\t\"%s\",", v.c_str());
    }
    DEBUG("    ]");

    /* (Pin) Executor of vuzzer requires absolute path of PUT binary */
    args[0] = fs::absolute(args[0]).native();

    using fuzzuf::algorithm::vuzzer::VUzzerSetting;
    using fuzzuf::algorithm::vuzzer::option::VUzzerTag;
    using fuzzuf::algorithm::vuzzer::option::GetDefaultOutfile;

    // Create VUzzerSetting
    std::shared_ptr<VUzzerSetting> setting(
        new VUzzerSetting(
            args,
            global_options.in_dir,
            global_options.out_dir,
            vuzzer_options.weight,
            vuzzer_options.full_dict,
            vuzzer_options.unique_dict,
            vuzzer_options.inst_bin,
            vuzzer_options.taint_db,
            vuzzer_options.taint_out,
            0, 0
        )
    );

    // PinToolExecutor needs the directory specified by "out_dir" to be already set up
    // so we need to create the directory first, and then initialize Executor
    SetupDirs(setting->out_dir.string());

    // Create PinToolExecutor
    // FIXME: TEST_BINARY_DIR macro should be used only for test codes. We must define a new macro in config.h.
    std::shared_ptr<PinToolExecutor> executor(
        new PinToolExecutor(
            FUZZUF_PIN_EXECUTABLE,
            {TEST_BINARY_DIR "/../tools/bbcounts2/bbcounts2.so", "-o", "bb.out", "-libc", "0"},
            setting->argv,
            setting->exec_timelimit_ms,
            setting->exec_memlimit,    
            setting->out_dir / GetDefaultOutfile()
            )
    );

    // Create PolyTrackerExecutor
    std::shared_ptr<PolyTrackerExecutor> taint_executor(
        new PolyTrackerExecutor(
            TEST_BINARY_DIR "/../tools/polyexecutor/polyexecutor.py",
            setting->path_to_inst_bin,
            setting->path_to_taint_db,
            setting->path_to_taint_file,
            setting->argv,
            setting->exec_timelimit_ms,
            setting->exec_memlimit,
            setting->out_dir / GetDefaultOutfile()
            )
    );

    // Create VUzzerState
    using fuzzuf::algorithm::vuzzer::VUzzerState;

    auto state = std::make_unique<VUzzerState>(setting, executor, taint_executor);

    return std::unique_ptr<TFuzzer>(
            dynamic_cast<TFuzzer *>(
                new TVUzzer(std::move(state))
            )
        );
}

#endif
