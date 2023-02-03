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
#define BOOST_TEST_MODULE algorithms.libfuzzer.initialize
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <array>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/corpus/add_to_initial_exec_input_set.hpp"
#include "fuzzuf/algorithms/libfuzzer/exec_input_set_range.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/algorithms/libfuzzer/select_seed.hpp"
#include "fuzzuf/algorithms/libfuzzer/test_utils.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/utils/node_tracer.hpp"
#include "fuzzuf/utils/not_random.hpp"
#include "fuzzuf/utils/which.hpp"

/**
 * Execute all initial inputs, add them to corpus and update corpus
 * distribution. This test checks that tasks listed above don't cause abort or
 * sanitizers to fire.
 */
BOOST_AUTO_TEST_CASE(Initialize) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";

  auto output_file_path = output_dir / "result";
  auto path_to_write_seed = output_dir / "cur_input";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  using fuzzuf::executor::LibFuzzerExecutorInterface;
  BOOST_TEST_CHECKPOINT("before init executor");
  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {fuzzuf::utils::which(fs::path("tee")).c_str(),
           output_file_path.native()},
          1000, 10000, false, path_to_write_seed, 1000, 1000)));
  BOOST_TEST_CHECKPOINT("after init executor");

  namespace lf = fuzzuf::algorithm::libfuzzer;
  lf::State state;
  state.create_info.config.debug = true;
  state.create_info.config.entropic.enabled = true;
  state.create_info.config.entropic.number_of_rarest_features = 10;
  state.create_info.config.entropic.feature_frequency_threshold = 3;
  state.create_info.config.entropic.scale_per_exec_time = false;
  std::minstd_rand rng;

  BOOST_TEST_CHECKPOINT("after init state");

  fuzzuf::exec_input::ExecInputSet initial_input;
  auto data1 = lf::test::getSeed1();
  lf::corpus::addToInitialExecInputSet(initial_input, data1);
  auto data2 = lf::test::getSeed2();
  lf::corpus::addToInitialExecInputSet(initial_input, data2);

  BOOST_TEST_CHECKPOINT("after init data");

  lf::FullCorpus corpus;

  for (auto data :
       initial_input | lf::adaptor::exec_input_set_range<
                           true, lf::ExecInputSetRangeInsertMode::NONE>) {
    lf::InputInfo testcase;
    std::vector<std::uint8_t> copied(data.begin(), data.end());
    std::vector<std::uint8_t> cov;
    std::vector<std::uint8_t> output;
    lf::executor::Execute(copied, output, cov, testcase, executor, 0u, true);
    lf::executor::CollectFeatures(state, corpus, copied, testcase, cov, 0U);
    lf::executor::AddToCorpus(
        state, corpus, copied, testcase, true, true, false, false, output_dir,
        [](std::string &&message) { std::cout << message << std::flush; });
  }

  BOOST_TEST_CHECKPOINT("after init corpus");

  lf::select_seed::UpdateDistribution<lf::MakeVersion(12U, 0U, 0U)>(
      state, corpus, rng, 100U, 20U,
      [](std::string &&message) { std::cout << message << std::flush; });

  BOOST_TEST_CHECKPOINT("after init distribution");

  std::string message;
  toString(message, state, 0, "  ");
  std::cout << message << std::endl;
  BOOST_TEST_CHECKPOINT("done");
}

/**
 * Execute all initial inputs, add them to corpus and update corpus distribution
 * using HierarFlow. This test checks that tasks listed above don't cause abort
 * or sanitizers to fire.
 */
BOOST_AUTO_TEST_CASE(HierarFlowExecute) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);

  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  using Ord = lf::test::Order;

  // Create input/output dirctory
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";

  auto output_file_path = output_dir / "result";
  auto path_to_write_seed = output_dir / "cur_input";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  using fuzzuf::executor::LibFuzzerExecutorInterface;

  BOOST_TEST_CHECKPOINT("before int executor");

  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {fuzzuf::utils::which(fs::path("tee")).c_str(),
           output_file_path.native()},
          1000, 10000, false, path_to_write_seed, 1000, 1000)));

  BOOST_TEST_CHECKPOINT("after init executor");

  lf::State state;
  state.create_info.config.debug = true;
  state.create_info.config.entropic.enabled = true;
  state.create_info.config.entropic.number_of_rarest_features = 10;
  state.create_info.config.entropic.feature_frequency_threshold = 3;
  state.create_info.config.entropic.scale_per_exec_time = false;

  BOOST_TEST_CHECKPOINT("after init state");

  fuzzuf::exec_input::ExecInputSet initial_input;
  auto data1 = lf::test::getSeed1();
  lf::corpus::addToInitialExecInputSet(initial_input, data1);
  auto data2 = lf::test::getSeed2();
  lf::corpus::addToInitialExecInputSet(initial_input, data2);

  BOOST_TEST_CHECKPOINT("after init data");

  auto for_each_initial_input = hf::CreateNode<lf::ForEachStaticData<
      lf::test::Full,
      lf::ExecInputSetRange<true, lf::ExecInputSetRangeInsertMode::NONE>,
      decltype(Ord::input)>>(
      initial_input |
      lf::adaptor::exec_input_set_range<true,
                                        lf::ExecInputSetRangeInsertMode::NONE>);
  auto create_input_info = hf::CreateNode<
      lf::StaticAssign<lf::test::Full, decltype(Ord::exec_result)>>();
  auto execute =
      hf::CreateNode<lf::standard_order::Execute<lf::test::Full, Ord>>();
  auto collect_features = hf::CreateNode<
      lf::standard_order::CollectFeatures<lf::test::Full, Ord>>();
  auto add_to_corpus =
      hf::CreateNode<lf::standard_order::AddToCorpus<lf::test::Full, Ord>>(
          true, true, false, false, output_dir,
          [](std::string &&message) { std::cout << message << std::flush; });
  auto update_distribution =
      hf::CreateNode<lf::standard_order::UpdateDistribution<
          lf::test::Full, lf::MakeVersion(12U, 0U, 0U), Ord>>(
          100U, 20U,
          [](std::string &&message) { std::cout << message << std::flush; });

  BOOST_TEST_CHECKPOINT("after init nodes");

  for_each_initial_input << create_input_info << execute << collect_features
                         << add_to_corpus << update_distribution;

  BOOST_TEST_CHECKPOINT("after init graph");

  lf::test::Variables vars;
  vars.executor = std::move(executor);
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << "trace : " << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;

  vars.begin_date = std::chrono::system_clock::now();
  hf::WrapToMakeHeadNode(for_each_initial_input)(vars, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });

  BOOST_TEST_CHECKPOINT("after execution");

  std::string message;
  toString(message, state, 0, "  ");
  std::cout << message << std::endl;

  BOOST_TEST_CHECKPOINT("done");
}
