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
#define BOOST_TEST_MODULE algorithms.libfuzzer.select_seed
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/algorithms/libfuzzer/select_seed.hpp"

#include <config.h>

#include <array>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/exec_input_set_range.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/algorithms/libfuzzer/test_utils.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/utils/node_tracer.hpp"
#include "fuzzuf/utils/not_random.hpp"
#include "fuzzuf/utils/which.hpp"

/**
 * Insert 1 input value to empty corpus, select an input from the corpus, and
 * check if first input and selected input are same.
 */
BOOST_AUTO_TEST_CASE(SelectSeed) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  auto data = lf::test::getSeed1();
  lf::State state;
  std::minstd_rand rng;
  lf::InputInfo testcase;
  testcase.enabled = true;
  lf::FullCorpus corpus;
  lf::corpus::AddToCorpus(corpus, data, testcase, false, fs::path("./"));
  lf::select_seed::UpdateDistribution<lf::MakeVersion(12U, 0U, 0U)>(
      state, corpus, rng, 100U, 20U,
      [](std::string &&message) { std::cout << message << std::flush; });
  lf::test::Range output;
  lf::select_seed::SelectSeed(state, corpus, rng, output, testcase, false);
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), output.begin(),
                                output.end());
}

/**
 * Check if the input value mutated 100 times is expected value.
 * This test detects code changes that causes mutation behaviour changes.
 */
BOOST_AUTO_TEST_CASE(Mutate) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;

  BOOST_TEST_CHECKPOINT("before init data");

  lf::test::Variables vars;

  lf::InputInfo testcase;
  testcase.enabled = true;
  auto data = lf::test::getSeed1();
  lf::corpus::AddToCorpus(vars.corpus, data, testcase, false, fs::path("./"));

  vars.rng.seed(1);

  BOOST_TEST_CHECKPOINT("after init data");

  lf::dictionary::StaticDictionary persistent_auto_dictionary;
  Load(TEST_DICTIONARY_DIR "/test.dict", persistent_auto_dictionary, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  BOOST_TEST_CHECKPOINT("after init dict");

  lf::select_seed::UpdateDistribution<lf::MakeVersion(12U, 0U, 0U)>(
      vars.state, vars.corpus, vars.rng, 100U, 20U,
      [](std::string &&message) { std::cout << message << std::flush; });

  BOOST_TEST_CHECKPOINT("after init corpus");
  using Ord = lf::test::Order;
  auto repeat = hf::CreateNode<lf::StaticRepeat<lf::test::Full>>(100);
  auto random =
      hf::CreateNode<lf::standard_order::RandomCall<lf::test::Full, Ord>>();
  auto select_input =
      hf::CreateNode<lf::standard_order::ChooseRandomSeed<lf::test::Full, Ord>>(
          false);
  auto select_crossover = hf::CreateNode<lf::ChooseRandomSeed<
      lf::test::Full, decltype(Ord::state && Ord::corpus && Ord::rng &&
                               Ord::crossover && Ord::exec_result)>>(true);

  auto erase_bytes =
      hf::CreateNode<lf::standard_order::EraseBytes<lf::test::Full, Ord>>();
  auto insert_byte =
      hf::CreateNode<lf::standard_order::InsertByte<lf::test::Full, Ord>>();
  auto insert_repeated_bytes = hf::CreateNode<
      lf::standard_order::InsertRepeatedBytes<lf::test::Full, Ord>>();
  auto change_byte =
      hf::CreateNode<lf::standard_order::ChangeByte<lf::test::Full, Ord>>();
  auto change_bit =
      hf::CreateNode<lf::standard_order::ChangeBit<lf::test::Full, Ord>>();
  auto shuffle_bytes =
      hf::CreateNode<lf::standard_order::ShuffleBytes<lf::test::Full, Ord>>();
  auto change_ascii_integer = hf::CreateNode<
      lf::standard_order::ChangeASCIIInteger<lf::test::Full, Ord>>();
  auto change_binary_integer = hf::CreateNode<
      lf::standard_order::ChangeBinaryInteger<lf::test::Full, Ord>>();
  auto copy_part =
      hf::CreateNode<lf::standard_order::CopyPart<lf::test::Full, Ord>>();
  auto crossover =
      hf::CreateNode<lf::standard_order::Crossover<lf::test::Full, Ord>>();
  auto manual_dict = hf::CreateNode<lf::standard_order::StaticDict<
      lf::test::Full, lf::dictionary::StaticDictionary, Ord>>();
  auto persistent_auto_dict = hf::CreateNode<lf::standard_order::StaticDict<
      lf::test::Full, lf::dictionary::StaticDictionary, Ord>>(
      std::move(persistent_auto_dictionary));
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;

  BOOST_TEST_CHECKPOINT("after init nodes");

  select_input << select_crossover << repeat
               << (random << (erase_bytes || insert_byte ||
                              insert_repeated_bytes || change_byte ||
                              change_bit || shuffle_bytes ||
                              change_ascii_integer || change_binary_integer ||
                              copy_part || crossover || manual_dict ||
                              persistent_auto_dict));

  BOOST_TEST_CHECKPOINT("after init graph");

  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << "trace : " << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;

  vars.begin_date = std::chrono::system_clock::now();
  hf::WrapToMakeHeadNode(select_input)(vars, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });

  BOOST_TEST_CHECKPOINT("after execution");

  const std::vector<std::uint8_t> expected{
      0x54U, 0x68U, 0x7cU, 0x66U, 0x75U, 0x67U, 0x66U, 0x75U, 0x67U, 0x61U,
      0x67U, 0x65U, 0x61U, 0x03U, 0x62U, 0xf9U, 0x91U, 0x63U, 0x58U, 0x65U,
      0x65U, 0x54U, 0x68U, 0x65U, 0x20U, 0x71U, 0x75U, 0x69U, 0x63U, 0x5aU,
      0x68U, 0x6fU, 0x67U, 0x65U, 0x0dU, 0x62U, 0xb8U, 0x12U, 0x68U, 0x00U,
      0x72U, 0xffU, 0xffU, 0x12U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x68U, 0x00U, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0x61U,
      0x03U, 0x62U, 0x91U, 0x63U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0x54U, 0x68U, 0x65U, 0x20U, 0x71U, 0x75U, 0x69U, 0x63U,
      0x6bU, 0x20U, 0x62U, 0x72U, 0x6fU, 0x77U, 0x6eU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0x72U, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xc0U, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xaaU, 0x6fU, 0x77U, 0x6eU, 0x20U, 0x66U, 0x6fU, 0x38U,
      0x20U, 0x66U, 0x6fU, 0x78U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0x6fU, 0x80U, 0xffU,
      0xffU, 0xffU, 0xffU, 0xefU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0x65U,
      0x20U, 0x71U, 0x75U, 0x69U, 0x63U, 0x6bU, 0x20U, 0x62U, 0x72U, 0x6fU,
      0x77U, 0x6eU, 0x20U, 0x66U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xf3U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
      0xffU, 0x07U, 0x00U, 0xbfU, 0xffU, 0xffU, 0x8bU, 0xffU, 0xffU, 0xffU,
      0x6bU, 0x20U, 0x62U, 0x72U, 0x6fU, 0x77U, 0xf9U, 0xffU, 0xffU, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0x66U, 0x75U, 0x67U, 0x61U, 0xf6U, 0xffU,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0x6eU, 0x20U,
      0x66U, 0x6eU, 0x20U, 0xd7U, 0x8dU, 0xedU, 0x66U, 0x9aU, 0xdfU, 0x61U,
      0xe5U, 0x62U, 0x8eU, 0x9dU, 0xa2U, 0x6fU, 0x8dU, 0x99U, 0x77U, 0x6eU,
      0x78U,
  };
  BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                vars.input[0].begin(), vars.input[0].end());
}
