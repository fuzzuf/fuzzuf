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
/**
 * @file fuzzer.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/libfuzzer/cli_compat/fuzzer.hpp"

#include <boost/program_options.hpp>
#include <cstdint>
#include <fstream>
#include <string>

#include "fuzzuf/algorithms/libfuzzer/cli_compat/options.hpp"
#include "fuzzuf/algorithms/libfuzzer/config.hpp"
#include "fuzzuf/algorithms/libfuzzer/create.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/logger/logger.hpp"

namespace fuzzuf::algorithm::libfuzzer {
LibFuzzer::LibFuzzer(cli::FuzzerArgs &fuzzer_args,
                     const cli::GlobalFuzzerOptions &global,
                     std::function<void(std::string &&)> &&sink_)
    : node_tracer([this](std::string &&m) { sink("trace : " + m); }) {
  Options opts;
  opts.output_dir = global.out_dir;
  auto [desc, pd] = createOptions(opts);

  if (!postProcess(fuzzer_args.global_options_description.add(desc), pd,
                   fuzzer_args.argc, fuzzer_args.argv, global, std::move(sink_),
                   opts)) {
    end_ = true;
    return;
  }
  create_info = opts.create_info;
  vars.state.create_info = opts.create_info;
  vars.rng = std::move(opts.rng);

  exec_input::ExecInputSet initial_inputs = loadInitialInputs(opts, vars.rng);
  vars.max_input_size =
      opts.create_info.len_control ? 4u : opts.create_info.max_input_length;
  sink = std::move(opts.sink);
  total_cycles = opts.total_cycles;
  print_final_stats = opts.print_final_stats;

  vars.begin_date = std::chrono::system_clock::now();
  const auto output_file_path = create_info.output_dir / "result";
  const auto path_to_write_seed = create_info.output_dir / "cur_input";
  const auto symcc_dir = create_info.output_dir / "symcc";
  vars.executors.reserve(opts.targets.size());
  std::size_t i = 0u;
  for (const auto &target_path : opts.targets) {
    if (i >= create_info.symcc_target_offset &&
        i < create_info.symcc_target_offset + create_info.symcc_target_count) {
      vars.executors.push_back(
          std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
              new fuzzuf::executor::NativeLinuxExecutor(
                  {target_path.string(), output_file_path.string()},
                  create_info.exec_timelimit_ms, create_info.exec_memlimit,
                  false, path_to_write_seed, create_info.afl_shm_size,
                  create_info.bb_shm_size, false,
                  {"SYMCC_OUTPUT_DIR=" + symcc_dir.string()}, {symcc_dir})));
    } else {
      vars.executors.push_back(
          std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
              new fuzzuf::executor::NativeLinuxExecutor(
                  {target_path.string(), output_file_path.string()},
                  create_info.exec_timelimit_ms, create_info.exec_memlimit,
                  create_info.forksrv, path_to_write_seed,
                  create_info.afl_shm_size, create_info.bb_shm_size)));
    }
    ++i;
  }
  {
    auto root = createInitialize<Func, Order>(opts.create_info, initial_inputs,
                                              false, sink);

    namespace hf = fuzzuf::hierarflow;
    hf::WrapToMakeHeadNode(root)(vars, node_tracer, ett);
  }
  auto runone_ =
      createRunone<Func, Order>(opts.create_info, initial_inputs, sink);
  namespace hf = fuzzuf::hierarflow;
  auto runone_wrapped = hf::WrapToMakeHeadNode(runone_);
  runone = [this, runone_wrapped = std::move(runone_wrapped)]() mutable {
    runone_wrapped(vars, node_tracer, ett);
  };

  DEBUG("[*] LibFuzzer::LibFuzzer(): Done");
}
void LibFuzzer::OneLoop() {
  // DEBUG("[*] LibFuzzer::OneLoop(): end_: %s", end_ ? "true" : "false");
  if (!end_) {
    runone();
    if (total_cycles >= 0 && vars.count >= std::size_t(total_cycles)) {
      end_ = true;
      if (print_final_stats) {
        std::string message;
        utils::toStringADL(message, vars.state, 0, "  ");
        sink(std::move(message));
        ett.dump(sink);
      }
    }
  }
}
}  // namespace fuzzuf::algorithm::libfuzzer
