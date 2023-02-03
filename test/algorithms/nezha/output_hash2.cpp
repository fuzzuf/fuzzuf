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
#define BOOST_TEST_MODULE algorithms.nezha.output_hash2
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <array>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/calc_max_length.hpp"
#include "fuzzuf/algorithms/libfuzzer/corpus/add_to_initial_exec_input_set.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/algorithms/libfuzzer/select_seed.hpp"
#include "fuzzuf/algorithms/libfuzzer/test_utils.hpp"
#include "fuzzuf/algorithms/nezha/create.hpp"
#include "fuzzuf/algorithms/nezha/hierarflow.hpp"
#include "fuzzuf/algorithms/nezha/state.hpp"
#include "fuzzuf/algorithms/nezha/test_utils.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/node_tracer.hpp"
#include "fuzzuf/utils/not_random.hpp"
#include "fuzzuf/utils/which.hpp"

/**
 * create()を使ってNezhaを組み立て、libFuzzerのデフォルトのサイクル数だけ回し、その過程でサニタイザにかかったりabortしたりしないことを確認する
 * 最後にfuzzerの状態と見つかった実装毎に挙動が変わる入力値をダンプする
 */
BOOST_AUTO_TEST_CASE(HierarFlowOutputHash) {
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
  namespace ne = fuzzuf::algorithm::nezha;
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
                          .set_reduce_inputs(false)
                          .set_reduce_depth(false)
                          .set_shrink(false))
          .set_exec_timelimit_ms(1000)
          .set_exec_memlimit(2147483648)
          .set_input_dir(input_dir)
          .set_output_dir(output_dir)
          .set_verbosity(2U)
          .set_seed(1U)
          .set_print_pcs(true)
          .set_print_final_stats(true)
          .set_total_cycles(250)
          .set_len_control(10)
          .emplace_dictionaries(
              std::vector<fs::path>{TEST_DICTIONARY_DIR "/csv.dict"});

  lf::test::Variables libfuzzer_variables;
  libfuzzer_variables.state.create_info = create_info;
  libfuzzer_variables.rng.seed(create_info.seed);
  ne::test::Variables nezha_variables;

  BOOST_TEST_CHECKPOINT("after init state");

  {
    const auto output_file_path = create_info.output_dir / "result";
    const auto path_to_write_seed = create_info.output_dir / "cur_input";
    std::vector<LibFuzzerExecutorInterface> executor;
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv", output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size, true)));
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv", output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size, true)));
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv_small",
             output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size, true)));
    libfuzzer_variables.executor = std::move(executor);
  }
  create_info.target_count = libfuzzer_variables.executor.size();

  BOOST_TEST_CHECKPOINT("after init executor");
  BOOST_CHECK_EQUAL(libfuzzer_variables.executor.size(), 3);

  fuzzuf::exec_input::ExecInputSet initial_input;
  lf::corpus::addToInitialExecInputSet(initial_input,
                                       std::vector<std::uint8_t>{'1'});
  if (create_info.max_input_length == 0U) {
    create_info.max_input_length = lf::CalcMaxLength(
        initial_input | lf::adaptor::exec_input_set_range<
                            true, lf::ExecInputSetRangeInsertMode::NONE>);
  }
  libfuzzer_variables.max_input_size =
      create_info.len_control ? 4u : create_info.max_input_length;

  auto root = ne::create<ne::test::Func, ne::test::Order>(
      create_info, true, initial_input,
      [](std::string &&m) { std::cout << m << std::flush; });

  libfuzzer_variables.begin_date = std::chrono::system_clock::now();
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << "trace : " << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(root)(libfuzzer_variables,
                                               nezha_variables, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });

  BOOST_TEST_CHECKPOINT("after execution");

  {
    const auto output_file_path = create_info.output_dir / "result";
    const auto path_to_write_seed = create_info.output_dir / "cur_input";
    std::vector<LibFuzzerExecutorInterface> executor;
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv_small",
             output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size, true)));
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv", output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size, true)));
    libfuzzer_variables.executor = std::move(executor);
  }

  BOOST_TEST_CHECKPOINT("after init executor for output");
  BOOST_CHECK_EQUAL(libfuzzer_variables.executor.size(), 2);

  {
    namespace tt = boost::test_tools;
    std::size_t solution_count = 0u;
    ne::known_outputs_t known;
    for (const auto &filename :
         fs::directory_iterator{create_info.output_dir}) {
      if (fs::is_regular_file(filename.status())) {
        auto mapped =
            fuzzuf::utils::map_file(filename.path().string(), O_RDONLY, true);
        std::vector<std::uint8_t> input(mapped.begin(), mapped.end());
        const auto leaf = filename.path().filename().string();
        static const auto expected_prefix = std::string("diff_");
        if (leaf.size() >= expected_prefix.size() &&
            std::equal(leaf.begin(),
                       std::next(leaf.begin(), expected_prefix.size()),
                       expected_prefix.begin(), expected_prefix.end())) {
          ne::outputs_t hash;
          {
            lf::InputInfo input_info;
            std::vector<std::uint8_t> output;
            std::vector<std::uint8_t> coverage;
            lf::executor::Execute(input, output, coverage, input_info,
                                  libfuzzer_variables.executor, 0u, true);
            hash.push_back(ne::output_hash()(output));
          }
          std::string output2;
          {
            lf::InputInfo input_info;
            std::vector<std::uint8_t> output;
            std::vector<std::uint8_t> coverage;
            lf::executor::Execute(input, output, coverage, input_info,
                                  libfuzzer_variables.executor, 1u, true);
            hash.push_back(ne::output_hash()(output));
          }
          // tuple of outputs is unique
          bool is_unique = known.insert(std::move(hash)).second;
          BOOST_CHECK(is_unique);
          ++solution_count;
        }
      }
    }
    std::cout << "The fuzzer detected " << solution_count << " solutions."
              << std::endl;
    // at least one solution was found
    BOOST_CHECK_NE(solution_count, 0u);
  }
  BOOST_TEST_CHECKPOINT("done");
}
