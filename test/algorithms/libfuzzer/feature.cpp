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
#define BOOST_TEST_MODULE algorithms.libfuzzer.feature
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

// この辺にテストの追加が必要

BOOST_AUTO_TEST_CASE(Feature) {
  auto data = fuzzuf::algorithm::libfuzzer::test::getSeed1();
}

#define FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR \
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");    \
  auto *const raw_dirname = mkdtemp(root_dir_template.data()); \
  BOOST_CHECK(raw_dirname != nullptr);                         \
  auto root_dir = fs::path(raw_dirname);                       \
  auto output_dir = root_dir / "output";                       \
  auto output_file_path = output_dir / "result";               \
  auto path_to_write_seed = output_dir / "cur_input";          \
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);   \
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }    \
  BOOST_SCOPE_EXIT_END                                         \
  namespace lf = fuzzuf::algorithm::libfuzzer;                 \
  namespace hf = fuzzuf::hierarflow;                           \
  namespace ut = fuzzuf::utils;                                \
  namespace sp = ut::struct_path;
using fuzzuf::executor::LibFuzzerExecutorInterface;

// Check if lf::executor::Execute can retrive standard output
BOOST_AUTO_TEST_CASE(ExecuteOutput) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {fuzzuf::utils::which(fs::path("wc")).c_str(), "-c"}, 1000, 10000,
          false, path_to_write_seed, 65536, 65536, true)));

  lf::InputInfo testcase;
  auto input = lf::test::getSeed1();
  std::vector<std::uint8_t> cov;
  std::vector<std::uint8_t> output;
  lf::executor::Execute(input, output, cov, testcase, executor, 0u, true);
  std::vector<std::uint8_t> expected_output{'1', '9', '\n'};
  BOOST_CHECK_EQUAL_COLLECTIONS(output.begin(), output.end(),
                                expected_output.begin(), expected_output.end());
}

// Check if Execute node can retrive standard output
BOOST_AUTO_TEST_CASE(HierarFlowExecuteOutput) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {fuzzuf::utils::which(fs::path("wc")).c_str(), "-c"}, 1000, 10000,
          false, path_to_write_seed, 65536, 65536, true)));

  constexpr static auto output_loc = sp::root / sp::arg<1>;
  using Ord =
      decltype(lf::test::Order::input && output_loc &&
               lf::test::Order::coverage && lf::test::Order::exec_result &&
               lf::test::Order::executors && lf::test::Order::executor_index &&
               lf::test::Order::use_afl_coverage);
  using WithOutput = bool(lf::test::Variables &, std::vector<std::uint8_t> &,
                          ut::DumpTracer &, ut::ElapsedTimeTracer &);
  auto node = hf::CreateNode<lf::Execute<WithOutput, Ord>>();

  lf::test::Variables variables;
  variables.executor = std::move(executor);
  auto input = lf::test::getSeed1();
  std::copy(input.begin(), input.end(), std::back_inserter(variables.input[0]));
  ut::DumpTracer tracer([](std::string &&m) { std::cout << m << std::flush; });
  ut::ElapsedTimeTracer ett;
  std::vector<std::uint8_t> output;
  fuzzuf::hierarflow::WrapToMakeHeadNode(node)(variables, output, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  std::vector<std::uint8_t> expected_output{'1', '9', '\n'};
  BOOST_CHECK_EQUAL_COLLECTIONS(output.begin(), output.end(),
                                expected_output.begin(), expected_output.end());
}

// Check if lf::executor::Execute can retrive execution result
BOOST_AUTO_TEST_CASE(ExecuteStatusSuccess) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {TEST_BINARY_DIR "/executor/ok"}, 1000, 10000, false,
          path_to_write_seed, 65536, 65536)));

  lf::InputInfo testcase;
  auto input = lf::test::getSeed1();
  std::vector<std::uint8_t> cov;
  std::vector<std::uint8_t> output;
  lf::executor::Execute(input, output, cov, testcase, executor, 0u, true);
  BOOST_CHECK(testcase.status ==
              fuzzuf::feedback::PUTExitReasonType::FAULT_NONE);
}

// Check if Execute node can retrive execution result
BOOST_AUTO_TEST_CASE(HierarFlowExecuteStatusSuccess) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {TEST_BINARY_DIR "/executor/ok"}, 1000, 10000, false,
          path_to_write_seed, 65536, 65536)));

  auto node = hf::CreateNode<
      lf::standard_order::Execute<lf::test::Full, lf::test::Order>>();

  lf::test::Variables variables;
  variables.executor = std::move(executor);
  auto input = lf::test::getSeed1();
  std::copy(input.begin(), input.end(), std::back_inserter(variables.input[0]));
  ut::DumpTracer tracer([](std::string &&m) { std::cout << m << std::flush; });
  ut::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(node)(variables, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  BOOST_CHECK(variables.exec_result.status ==
              fuzzuf::feedback::PUTExitReasonType::FAULT_NONE);
}

// Check if lf::executor::Execute can retrive execution result that is expected
// to be "crashed"
BOOST_AUTO_TEST_CASE(ExecuteStatusAbort) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {TEST_BINARY_DIR "/executor/abort"}, 1000, 10000, false,
          path_to_write_seed, 65536, 65536)));

  lf::InputInfo testcase;
  auto input = lf::test::getSeed1();
  std::vector<std::uint8_t> cov;
  std::vector<std::uint8_t> output;
  lf::executor::Execute(input, output, cov, testcase, executor, 0u, true);
  BOOST_CHECK(testcase.status ==
              fuzzuf::feedback::PUTExitReasonType::FAULT_CRASH);
}

// Check if Execute node can retrive execution result that is expected to be
// "crashed" Since Executor is tested for each results in it's own tests, tests
// in this file don't cover all cases.
BOOST_AUTO_TEST_CASE(HierarFlowExecuteAbort) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {TEST_BINARY_DIR "/executor/abort"}, 1000, 10000, false,
          path_to_write_seed, 65536, 65536)));

  auto node = hf::CreateNode<
      lf::standard_order::Execute<lf::test::Full, lf::test::Order>>();

  lf::test::Variables variables;
  variables.executor = std::move(executor);
  auto input = lf::test::getSeed1();
  std::copy(input.begin(), input.end(), std::back_inserter(variables.input[0]));
  ut::DumpTracer tracer([](std::string &&m) { std::cout << m << std::flush; });
  ut::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(node)(variables, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  BOOST_CHECK(variables.exec_result.status ==
              fuzzuf::feedback::PUTExitReasonType::FAULT_CRASH);
}

#ifdef FUZZTOYS_FOUND
// Check if lf::execute::Execute can retrive coverage
BOOST_AUTO_TEST_CASE(ExecuteCoverage) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-brainf_ck"}, 1000, 10000, false,
          path_to_write_seed, 65536, 65536)));

  lf::InputInfo testcase;
  std::vector<std::uint8_t> input{'+'};
  std::vector<std::uint8_t> cov;
  std::vector<std::uint8_t> output;
  lf::executor::Execute(input, output, cov, testcase, executor, 0u, true);
  const auto non_zero_count =
      std::count_if(cov.begin(), cov.end(), [](auto v) { return v != 0u; });
  BOOST_CHECK_NE(non_zero_count, 0u);
}

// Check if Execute node can retrive coverage
BOOST_AUTO_TEST_CASE(HierarFlowExecuteCoverage) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_FEATURE_PREPARE_OUTDIR
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  std::vector<LibFuzzerExecutorInterface> executor;
  executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
      new fuzzuf::executor::NativeLinuxExecutor(
          {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-brainf_ck"}, 1000, 10000, false,
          path_to_write_seed, 65536, 65536)));

  auto node = hf::CreateNode<
      lf::standard_order::Execute<lf::test::Full, lf::test::Order>>();

  lf::test::Variables variables;
  variables.executor = std::move(executor);
  std::vector<std::uint8_t> input{'+'};
  std::copy(input.begin(), input.end(), std::back_inserter(variables.input[0]));
  ut::DumpTracer tracer([](std::string &&m) { std::cout << m << std::flush; });
  ut::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(node)(variables, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  const auto non_zero_count =
      std::count_if(variables.coverage.begin(), variables.coverage.end(),
                    [](auto v) { return v != 0u; });
  BOOST_CHECK_NE(non_zero_count, 0u);
}
#endif

/*
 * Nodes which should be tested here but not yet.
 * AddToSolution
 * CollectFeatures
 * IfNewCoverage
 * PrintStatusForNewUnit
 * UpdateDistribution
 *
 * Functions which should be tested here but not yet.
 * executor
 *   CollectFeatures
 *   AddToCorpus
 *   AddToSolution
 *   PrintStatusForNewUnit
 * feature
 *   ForEachNonZeroByte
 *   CollectFeatures
 *   AddRareFeature
 *   AddFeature
 *   UpdateFeatureFrequency
 * corpus
 *   AddToCorpus
 *   replaceCorpus
 *   addToInitialExecInputSet
 *   deleteInput
 *
 */
