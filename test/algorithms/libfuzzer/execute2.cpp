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
#define BOOST_TEST_MODULE algorithms.libfuzzer.execute2
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <array>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/calc_max_length.hpp"
#include "fuzzuf/algorithms/libfuzzer/corpus/add_to_initial_exec_input_set.hpp"
#include "fuzzuf/algorithms/libfuzzer/create.hpp"
#include "fuzzuf/algorithms/libfuzzer/exec_input_set_range.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/algorithms/libfuzzer/select_seed.hpp"
#include "fuzzuf/algorithms/libfuzzer/test_utils.hpp"
#include "fuzzuf/executor/libfuzzer_executor_interface.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/node_tracer.hpp"
#include "fuzzuf/utils/not_random.hpp"
#include "fuzzuf/utils/sha1.hpp"
#include "fuzzuf/utils/which.hpp"

/**
 * create()を使ってlibFuzzerを組み立て、libFuzzerのデフォルトのサイクル数だけ回し、その過程でサニタイザにかかったりabortしたりしないことを確認する
 * 最後にfuzzerの状態と見つかったクラッシュパスをダンプする
 */
BOOST_AUTO_TEST_CASE(HierarFlowExecute) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";

  // Create input/output dirctory

  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  using fuzzuf::executor::LibFuzzerExecutorInterface;

  BOOST_TEST_CHECKPOINT("before init state");

  auto create_info =
      lf::FuzzerCreateInfo()
          .set_config(lf::Config()
                          .set_debug(true)
                          .set_entropic(lf::EntropicConfig()
                                            .set_enabled(true)
                                            .set_number_of_rarest_features(10)
                                            .set_feature_frequency_threshold(3)
                                            .set_scale_per_exec_time(false))
                          .set_reduce_inputs(true)
                          .set_reduce_depth(true)
                          .set_shrink(true))
          .set_input_dir(input_dir)
          .set_output_dir(output_dir)
          .set_verbosity(2U)
          .set_seed(1U)
          .set_print_pcs(true)
          .set_print_final_stats(true)
          .set_total_cycles(1000)
          .set_len_control(10)
          .emplace_dictionaries(
              std::vector<fs::path>{TEST_DICTIONARY_DIR "/brainf_ck.dict"});

  lf::test::Variables vars;
  vars.state.create_info = create_info;
  vars.rng.seed(create_info.seed);

  BOOST_TEST_CHECKPOINT("after init state");
  {
    const auto output_file_path = create_info.output_dir / "result";
    const auto path_to_write_seed = create_info.output_dir / "cur_input";
    std::vector<LibFuzzerExecutorInterface> executor;
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-brainf_ck",
             output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size)));
    vars.executor = std::move(executor);
  }
  BOOST_CHECK_EQUAL(vars.executor.size(), 1);

  BOOST_TEST_CHECKPOINT("after init executor");

  fuzzuf::exec_input::ExecInputSet initial_inputs;
  const auto data = std::vector<uint8_t>{'+'};
  lf::corpus::addToInitialExecInputSet(initial_inputs, data);
  if (create_info.max_input_length == 0U) {
    create_info.max_input_length = lf::CalcMaxLength(
        initial_inputs | lf::adaptor::exec_input_set_range<
                             true, lf::ExecInputSetRangeInsertMode::NONE>);
  }
  vars.max_input_size =
      create_info.len_control ? 4u : create_info.max_input_length;

  auto root = lf::create<lf::test::Full, lf::test::Order>(
      create_info, initial_inputs,
      [](std::string &&m) { std::cout << m << std::flush; });

  BOOST_TEST_CHECKPOINT("after init graph");

  vars.begin_date = std::chrono::system_clock::now();
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << "trace : " << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;
  hf::WrapToMakeHeadNode(root)(vars, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });

  BOOST_TEST_CHECKPOINT("after execution");
  {
    std::size_t solution_count = 0u;
    for (const auto &filename :
         fs::directory_iterator{create_info.output_dir}) {
      if (fs::is_regular_file(filename.status())) {
        auto mapped =
            fuzzuf::utils::map_file(filename.path().string(), O_RDONLY, true);
        std::vector<std::uint8_t> input(mapped.begin(), mapped.end());
        auto sha1 = fuzzuf::utils::ToSerializedSha1(input);
        if (sha1 != filename.path().filename().string()) continue;
        std::vector<std::uint8_t> output;
        std::vector<std::uint8_t> coverage;
        lf::InputInfo input_info;
        lf::executor::Execute(input, output, coverage, input_info,
                              vars.executor, 0u, true);
        // target fails to execute found inputs
        ++solution_count;
      }
    }
    std::cout << "The fuzzer detected " << solution_count << " solutions."
              << std::endl;
    // at least one solution was found
    BOOST_CHECK_NE(solution_count, 0u);
  }
  BOOST_TEST_CHECKPOINT("done");
}
