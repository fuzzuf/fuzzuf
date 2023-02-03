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
#define BOOST_TEST_MODULE algorithms.libfuzzer.mutator
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/dictionary.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/test_utils.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/utils/node_tracer.hpp"
#include "fuzzuf/utils/not_random.hpp"

/**
 * libFuzzerのmutator
 * EraseBytesにテストデータを渡してテストデータの一部が削除されることを確認する
 */
BOOST_AUTO_TEST_CASE(EraseBytes) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  lf::MutationHistory history;
  const auto size1 = lf::mutator::EraseBytes(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 18U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'T', 'e', ' ', 'q', 'u', 'i', 'c', 'k', ' ',
                                  'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  const auto size2 = lf::mutator::EraseBytes(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 15U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{'T', 'e', ' ', 'c', 'k', ' ', 'b', 'r',
                                  'o', 'w', 'n', ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
}

/**
 * libFuzzerのmutator
 * InsertByteにテストデータを渡してテストデータに1バイトの値が挿入されることを確認する
 */
BOOST_AUTO_TEST_CASE(InsertByte) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  rng.seed(123U);
  lf::MutationHistory history;
  const auto size1 = lf::mutator::InsertByte(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 20U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'T', 'h', 'e', '|', ' ', 'q', 'u',
                                  'i', 'c', 'k', ' ', 'b', 'r', 'o',
                                  'w', 'n', ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  const auto size2 = lf::mutator::InsertByte(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 21U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{'T', 'h', 'e', '|', ' ', 'q', 'u',
                                  'i', 'c', 'k', ' ', 'b', 'r', 'o',
                                  'w', 'n', ' ', 'f', 'o', 'x', '~'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
}

/**
 * libFuzzerのmutator
 * InsertRepeatedBytesにテストデータを渡してテストデータに0x00の列または0xffの列が挿入されることを確認する
 */
BOOST_AUTO_TEST_CASE(InsertRepeatedBytes) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  lf::MutationHistory history;
  rng.seed(3U);
  const auto size1 =
      lf::mutator::InsertRepeatedBytes(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 25U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'T', 'h', 'e', ' ', 0U,  0U,  0U,  0U,  0U,
                                  0U,  'q', 'u', 'i', 'c', 'k', ' ', 'b', 'r',
                                  'o', 'w', 'n', ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  rng.seed(2U);
  const auto size2 =
      lf::mutator::InsertRepeatedBytes(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 30U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{'T', 'h', 'e', 0xff, 0xff, 0xff, 0xff, 0xff,
                                  ' ', 0U,  0U,  0U,   0U,   0U,   0U,   'q',
                                  'u', 'i', 'c', 'k',  ' ',  'b',  'r',  'o',
                                  'w', 'n', ' ', 'f',  'o',  'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
}

/**
 * libFuzzerのmutator
 * ChangeByteにテストデータを渡してテストデータのうち1バイトが別の値に書き換えられることを確認する
 */
BOOST_AUTO_TEST_CASE(ChangeByte) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  lf::MutationHistory history;
  rng.seed(7U);
  const auto size1 = lf::mutator::ChangeByte(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'T',  'h', 'e', ' ', 'q', 'u', 'i',
                                  0x08, 'k', ' ', 'b', 'r', 'o', 'w',
                                  'n',  ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  const auto size2 = lf::mutator::ChangeByte(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{'T',  'h', 'e',  ' ', 'q', 'u', 'i',
                                  0x08, 'k', 0x0a, 'b', 'r', 'o', 'w',
                                  'n',  ' ', 'f',  'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
}

/**
 * libFuzzerのmutator
 * ChangeByteにテストデータを渡してテストデータのうち1バイトが別の値に書き換えられることを確認する
 */
BOOST_AUTO_TEST_CASE(ChangeBit) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  lf::MutationHistory history;
  rng.seed(7U);
  const auto size1 = lf::mutator::ChangeBit(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'T',  'h', 'e', ' ', 'q', 'u', 'i',
                                  0x62, 'k', ' ', 'b', 'r', 'o', 'w',
                                  'n',  ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  const auto size2 = lf::mutator::ChangeBit(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{'T',  'h', 'e',  ' ', 'q', 'u', 'i',
                                  0x62, 'k', 0x24, 'b', 'r', 'o', 'w',
                                  'n',  ' ', 'f',  'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
}

/**
 * libFuzzerのmutator
 * ShuffleBytesにテストデータを渡してテストデータをソートしたものがmutationの前後で変化していないことを確認する
 */
BOOST_AUTO_TEST_CASE(ShuffleBytes) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  lf::MutationHistory history;
  rng.seed(2U);
  const auto size1 = lf::mutator::ShuffleBytes(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  lf::test::Range expected = lf::test::getSeed1();
  std::sort(expected.begin(), expected.end());
  std::sort(data.begin(), data.end());
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),
                                expected.end());
  const auto size2 = lf::mutator::ShuffleBytes(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  std::sort(data.begin(), data.end());
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),
                                expected.end());
}

/**
 * libFuzzerのmutator
 * ChangeASCIIIntegerに数値を含むJSONをt渡して数値の部分が別の値に書き変わる事を確認する
 */
BOOST_AUTO_TEST_CASE(ChangeASCIIInteger) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  lf::test::Range data{'{', ' ', '"', 'w', 'i', 'd', 't', 'h', '"', ':', ' ',
                       '1', '0', '0', ',', ' ', '"', 'h', 'e', 'g', 'i', 'h',
                       't', ':', ' ', '"', '3', '5', '"', ' ', '}'};
  lf::test::RNG rng;
  rng.seed(71U);
  lf::MutationHistory history;
  const auto size1 =
      lf::mutator::ChangeASCIIInteger(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 31U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'{', ' ', '"', 'w', 'i', 'd', 't', 'h',
                                  '"', ':', ' ', '0', '5', '0', ',', ' ',
                                  '"', 'h', 'e', 'g', 'i', 'h', 't', ':',
                                  ' ', '"', '3', '5', '"', ' ', '}'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  const auto size2 =
      lf::mutator::ChangeASCIIInteger(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 31U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{'{', ' ', '"', 'w', 'i', 'd', 't', 'h',
                                  '"', ':', ' ', '0', '7', '5', ',', ' ',
                                  '"', 'h', 'e', 'g', 'i', 'h', 't', ':',
                                  ' ', '"', '3', '5', '"', ' ', '}'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
  rng.seed(15U);
  const auto size3 =
      lf::mutator::ChangeASCIIInteger(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 31U);
  BOOST_CHECK_EQUAL(data.size(), size3);
  const lf::test::Range expected3{'{', ' ', '"', 'w', 'i', 'd', 't', 'h',
                                  '"', ':', ' ', '0', '7', '5', ',', ' ',
                                  '"', 'h', 'e', 'g', 'i', 'h', 't', ':',
                                  ' ', '"', '3', '4', '"', ' ', '}'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected3.begin(),
                                expected3.end());
}

/**
 * libFuzzerのmutator
 * ChangeBinaryIntegerにテストデータを渡して、テストデータの一部がインクリメントされ、別の一部が符号を反転される事を確認する
 */
BOOST_AUTO_TEST_CASE(ChangeBinaryInteger) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  lf::MutationHistory history;
  rng.seed(71U);
  const auto size1 =
      lf::mutator::ChangeBinaryInteger(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'T', 'h', 'e', ' ', 'q', 'u', 'i',
                                  'd', 'k', ' ', 'b', 'r', 'o', 'w',
                                  'n', ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  rng.seed(30U);
  const auto size2 =
      lf::mutator::ChangeBinaryInteger(rng, data, 40000U, history);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{'T', 'h',  'e',  ' ',  'q', 'u', 'i',
                                  'd', 'k',  ' ',  'b',  'r', 'o', 'w',
                                  'n', 0xde, 0x99, 0x90, 0x87};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
}

/**
 * libFuzzerのmutator
 * Crossoverに2つのテストデータを渡して、2つのテストデータの値を混ぜ合わせた物が出来る事を確認する
 */
BOOST_AUTO_TEST_CASE(Crossover) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  lf::MutationHistory history;
  auto crossover_with = lf::test::getSeed2();
  rng.seed(71U);
  const auto size1 =
      lf::mutator::Crossover(rng, data, 40000U, history, crossover_with);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'T', 'h', 'e', ' ', 'q', 'u', 'i',
                                  'c', 'k', ' ', 'b', 'r', 'o', 'w',
                                  'n', 'e', 'r', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  const auto size2 =
      lf::mutator::Crossover(rng, data, 40000U, history, crossover_with);
  BOOST_CHECK_EQUAL(data.size(), 42U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{
      'T', 'h', 'j', 'u', 'm', 'p', 's', ' ', 'o', 'v', 'e', 'r', 'e', ' ',
      'q', 'u', 'i', 'c', 'k', ' ', 'b', 'r', 'o', 'w', ' ', 't', 'h', 'n',
      'e', 'e', ' ', 'l', 'r', 'o', 'x', 'a', 'z', 'y', ' ', 'd', 'o', 'g'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
  rng.seed(84U);
  const auto size3 =
      lf::mutator::Crossover(rng, data, 40000U, history, crossover_with);
  BOOST_CHECK_EQUAL(data.size(), 65U);
  BOOST_CHECK_EQUAL(data.size(), size3);
  const lf::test::Range expected3{
      'T', 'h', 'j', 'j', 'u', 'm', 'p', 's', ' ', 'o', 'v', 'e', 'r',
      ' ', 't', 'h', 'e', ' ', 'l', 'a', 'z', 'y', 'u', 'm', 'p', 's',
      ' ', 'o', 'v', 'e', 'r', 'e', ' ', ' ', 'd', 'q', 'u', 'i', 'c',
      'k', ' ', 'b', 'o', 'g', 'r', 'o', 'w', ' ', 't', 'h', 'n', 'e',
      'e', ' ', 'l', 'r', 'o', 'x', 'a', 'z', 'y', ' ', 'd', 'o', 'g'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected3.begin(),
                                expected3.end());
}

/**
 * libFuzzerのmutator
 * *Dictにテストデータを渡して、テストデータにtest.dictの中の単語が挿入または上書きされる事を確認する
 */
BOOST_AUTO_TEST_CASE(Dict) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  lf::test::RNG rng;
  lf::MutationHistory history;
  lf::dictionary::StaticDictionary dict;
  Load(TEST_DICTIONARY_DIR "/test.dict", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });
  rng.seed(71U);
  std::vector<
      fuzzuf::utils::range::RangeValueT<lf::dictionary::StaticDictionary> *>
      dict_entry;
  const auto size1 =
      lf::mutator::Dictionary(rng, data, 40000U, history, dict_entry, dict);
  BOOST_CHECK_EQUAL(data.size(), 19U);
  BOOST_CHECK_EQUAL(data.size(), size1);
  const lf::test::Range expected1{'T', 'h', 'e', ' ', 'q', 'u', 'i',
                                  'c', 'k', 'f', 'u', 'g', 'a', 'w',
                                  'n', ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
  rng.seed(18U);
  const auto size2 =
      lf::mutator::Dictionary(rng, data, 40000U, history, dict_entry, dict);
  BOOST_CHECK_EQUAL(data.size(), 23U);
  BOOST_CHECK_EQUAL(data.size(), size2);
  const lf::test::Range expected2{'h', 'o', 'g', 'e', 'T', 'h', 'e', ' ',
                                  'q', 'u', 'i', 'c', 'k', 'f', 'u', 'g',
                                  'a', 'w', 'n', ' ', 'f', 'o', 'x'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected2.begin(),
                                expected2.end());
}

/**
 * libFuzzerの各mutatorが直接呼び出した場合とHierarFlowを経由して呼び出した場合で同じ結果になる事を確認する
 */
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(EraseBytes, EraseBytes,
                                                  EraseBytes)
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(InsertByte, InsertByte,
                                                  InsertByte)
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(InsertRepeatedBytes,
                                                  InsertRepeatedBytes,
                                                  InsertRepeatedBytes)
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(ChangeByte, ChangeByte,
                                                  ChangeByte)
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(ChangeBit, ChangeBit,
                                                  ChangeBit)
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(ShuffleBytes, ShuffleBytes,
                                                  ShuffleBytes)
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(ChangeASCIIInteger,
                                                  ChangeASCIIInteger,
                                                  ChangeASCIIInteger)
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(ChangeBinaryInteger,
                                                  ChangeBinaryInteger,
                                                  ChangeBinaryInteger)
FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(CopyPart, CopyPart, CopyPart)
// FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE( Dump, dump )

/**
 * libFuzzerのmutator
 * Crossoverが直接呼び出した場合とHierarFlowを経由して呼び出した場合で同じ結果になる事を確認する
 */
BOOST_AUTO_TEST_CASE(HierarFlowCrossover) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  auto data = lf::test::getSeed1();
  auto expected = lf::test::getSeed1();
  auto crossover = lf::test::getSeed2();

  {
    using Ord = lf::test::Order;
    auto node =
        hf::CreateNode<lf::standard_order::Crossover<lf::test::Full, Ord>>();
    lf::test::Variables vars;
    std::copy(data.begin(), data.end(), std::back_inserter(vars.input[0]));
    std::copy(crossover.begin(), crossover.end(),
              std::back_inserter(vars.input[1]));
    fuzzuf::utils::DumpTracer tracer(
        [](std::string &&m) { std::cout << m << std::flush; });
    fuzzuf::utils::ElapsedTimeTracer ett;
    hf::WrapToMakeHeadNode(node)(vars, tracer, ett);
    data.clear();
    std::copy(vars.input[0].begin(), vars.input[0].end(),
              std::back_inserter(data));
    ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  }
  {
    std::minstd_rand rng;
    lf::MutationHistory history;
    lf::mutator::Crossover(rng, expected, 40000U, history, crossover);
  }
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),
                                expected.end());
}
/*
BOOST_AUTO_TEST_CASE(HierarFlowCrossoverLogicalOr) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  auto data = lf::test::getSeed1();
  auto expected = data;
  auto crossover = lf::test::getSeed2();

  {
    lf::State state;
    auto node1 = hf::CreateNode<
        lf::Crossover<lf::test::partial_t, lf::test::rng_index,
                      lf::test::input_index, lf::test::max_length_index,
                      lf::test::history_index, lf::test::crossover_index>>();
    auto node2 = hf::CreateNode<
        lf::Crossover<lf::test::partial_t, lf::test::rng_index,
                      lf::test::input_index, lf::test::max_length_index,
                      lf::test::history_index, lf::test::crossover_index>>();
    auto nop = hf::CreateNode<lf::Nop<lf::test::partial_t>>();
    nop << ( node1 || node2 );
    lf::FullCorpus corpus;
    lf::FullCorpus solutions;
    lf::FullCorpus merger;
    std::minstd_rand rng;
    hf::WrapToMakeHeadNode( nop )(
        state, corpus, solutions, merger, rng, data, 40000U,
        lf::MutationHistory(), crossover, lf::test::dict_t(),
        std::vector<fuzzuf::utils::range::RangeValueT<lf::test::dict_t> *>());
  }
  {
    std::minstd_rand rng;
    lf::MutationHistory history;
    lf::mutator::crossover(rng, expected, 40000U, history, crossover);
    lf::mutator::crossover(rng, expected, 40000U, history, crossover);
  }
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),
                                expected.end());
}
*/
BOOST_AUTO_TEST_CASE(HierarFlowCrossoverShiftLeft) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  auto data = lf::test::getSeed1();
  auto expected = lf::test::getSeed1();
  auto crossover = lf::test::getSeed2();

  {
    using Ord = lf::test::Order;
    auto node1 =
        hf::CreateNode<lf::standard_order::Crossover<lf::test::Full, Ord>>();
    auto node2 =
        hf::CreateNode<lf::standard_order::Crossover<lf::test::Full, Ord>>();
    node1 << node2;
    lf::test::Variables vars;
    std::copy(data.begin(), data.end(), std::back_inserter(vars.input[0]));
    std::copy(crossover.begin(), crossover.end(),
              std::back_inserter(vars.input[1]));
    fuzzuf::utils::DumpTracer tracer(
        [](std::string &&m) { std::cout << m << std::flush; });
    fuzzuf::utils::ElapsedTimeTracer ett;
    hf::WrapToMakeHeadNode(node1)(vars, tracer, ett);
    data.clear();
    std::copy(vars.input[0].begin(), vars.input[0].end(),
              std::back_inserter(data));
    ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  }
  {
    std::minstd_rand rng;
    lf::MutationHistory history;
    lf::mutator::Crossover(rng, expected, 40000U, history, crossover);
    lf::mutator::Crossover(rng, expected, 40000U, history, crossover);
  }
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),
                                expected.end());
}

/**
 * libFuzzerのMaskにテストデータを渡して、マスク中のデータの先頭を書き換え、マスクを解除するとマスク範囲の先頭だったバイトが書き換わっている事を確認する
 */
BOOST_AUTO_TEST_CASE(Mask) {
  auto data = fuzzuf::algorithm::libfuzzer::test::getSeed1();
  const std::vector<int> mask{0, 1, 1, 0, 0, 1, 0, 1, 1, 1};
  const std::vector<std::uint8_t> expected{'h', 'e', 'u', 'c', 'k', ' '};
  std::vector<std::uint8_t> masked;
  fuzzuf::algorithm::libfuzzer::mutator::Mask(data, mask, masked);
  BOOST_CHECK_EQUAL(masked.size(), 6U);
  BOOST_CHECK_EQUAL_COLLECTIONS(masked.begin(), masked.end(), expected.begin(),
                                expected.end());
  masked[0] = 'x';
  std::vector<std::uint8_t> unmasked = data;
  data[1] = 'x';
  fuzzuf::algorithm::libfuzzer::mutator::Unmask(masked, mask, unmasked);
  BOOST_CHECK_EQUAL(unmasked.size(), data.size());
  BOOST_CHECK_EQUAL_COLLECTIONS(unmasked.begin(), unmasked.end(), data.begin(),
                                data.end());
}

/**
 * libFuzzerのMaskが直接読んだ場合とHierarFlowのStaticMaskを経由して呼んだ場合で同じ結果になる事を確認する
 */
BOOST_AUTO_TEST_CASE(HierarFlowStaticMask) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  auto data = lf::test::getSeed1();
  lf::test::Range mask_{0, 1, 1, 0, 0, 1, 0, 1, 1, 1};
  const lf::test::Range expected{'T', 'h', 'e', ' ', 'q', 'c', 'i', 'k', ' ',
                                 'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x'};

  using Ord = lf::test::Order;
  auto mask = hf::CreateNode<
      lf::standard_order::StaticMask<lf::test::Full, lf::test::Range, Ord>>(
      std::move(mask_));
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR(EraseBytes, erase_bytes)
  mask << erase_bytes;
  lf::test::Variables vars;
  vars.rng.seed(123U);
  std::copy(data.begin(), data.end(), std::back_inserter(vars.input[0]));
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(mask)(vars, tracer, ett);
  data.clear();
  std::copy(vars.input[0].begin(), vars.input[0].end(),
            std::back_inserter(data));
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),
                                expected.end());
}

/**
 * libFuzzerのMaskが直接読んだ場合とHierarFlowのDynamicMaskを経由して呼んだ場合で同じ結果になる事を確認する
 */
BOOST_AUTO_TEST_CASE(HierarFlowDynamicMask) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  auto data = lf::test::getSeed1();
  const lf::test::Range mask_{0, 1, 1, 0, 0, 1, 0, 1, 1, 1};
  const lf::test::Range expected{'T', 'h', 'e', ' ', 'q', 'c', 'i', 'k', ' ',
                                 'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x'};

  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  // get_mask( state ) = mask_;
  using Ord = lf::test::Order;
  auto mask =
      hf::CreateNode<lf::standard_order::DynamicMask<lf::test::Full, Ord>>();
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR(EraseBytes, erase_bytes)
  mask << erase_bytes;
  lf::test::Variables vars;
  vars.rng.seed(123U);
  std::copy(data.begin(), data.end(), std::back_inserter(vars.input[0]));
  std::copy(mask_.begin(), mask_.end(), std::back_inserter(vars.input[2]));
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(mask)(vars, tracer, ett);
  data.clear();
  std::copy(vars.input[0].begin(), vars.input[0].end(),
            std::back_inserter(data));
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),
                                expected.end());
}

/**
 * libFuzzerのStaticRepeatを使ってテストデータにEraseBytesを10回かけた結果がテストデータの中の'j'だけが残っている状態になっている事を確認する
 */
BOOST_AUTO_TEST_CASE(HierarFlowStaticRepeat) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  lf::test::Range data = lf::test::getSeed2();
  const lf::test::Range expected{'j'};

  auto repeat = hf::CreateNode<lf::StaticRepeat<lf::test::Full>>(10);
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR(EraseBytes, erase_bytes)
  repeat << (erase_bytes);
  lf::test::Variables vars;
  vars.rng.seed(5U);
  std::copy(data.begin(), data.end(), std::back_inserter(vars.input[0]));
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(repeat)(vars, tracer, ett);
  data.clear();
  std::copy(vars.input[0].begin(), vars.input[0].end(),
            std::back_inserter(data));
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),
                                expected.end());
}

/**
 * このテストは結果をチェックする必要がある
 */
BOOST_AUTO_TEST_CASE(HierarFlowDynamicRepeat) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  using Ord = lf::test::Order;
  namespace sp = fuzzuf::utils::struct_path;
  auto repeat = hf::CreateNode<lf::DynamicRepeat<
      lf::test::Full,
      decltype(sp::root / sp::ident<std::less<std::size_t>> && Ord::count &&
               sp::root / sp::int_<std::size_t, 10U>)>>();
  auto append =
      hf::CreateNode<lf::StaticAppend<lf::test::Full, decltype(Ord::count)>>(
          1U);
  lf::test::Variables vars;
  // initial value is 0
  vars.count = 0u;
  vars.rng.seed(5U);
  // increment 10 times
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;
  repeat << (append);
  fuzzuf::hierarflow::WrapToMakeHeadNode(repeat)(vars, tracer, ett);
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  // the final value should be 10
  BOOST_CHECK_EQUAL(vars.count, 10u);
}

/**
 * check "if" node works properly
 */
BOOST_AUTO_TEST_CASE(HierarFlowIf) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  using Ord = lf::test::Order;
  namespace sp = fuzzuf::utils::struct_path;
  auto if_ = hf::CreateNode<
      lf::If<lf::test::Full,
             decltype(sp::root / sp::ident<std::less<std::size_t>> &&
                      Ord::count && sp::root / sp::int_<std::size_t, 2U>)>>();
  auto append =
      hf::CreateNode<lf::StaticAppend<lf::test::Full, decltype(Ord::count)>>(
          1U);
  // increment until 2
  if_ << append;
  auto wrapped = fuzzuf::hierarflow::WrapToMakeHeadNode(if_);
  lf::test::Variables vars;
  // initial value is 0
  vars.count = 0u;
  vars.rng.seed(5U);
  // 0 -> 1
  {
    fuzzuf::utils::DumpTracer tracer(
        [](std::string &&m) { std::cout << m << std::flush; });
    fuzzuf::utils::ElapsedTimeTracer ett;
    wrapped(vars, tracer, ett);
    ett.dump([](std::string &&m) { std::cout << m << std::flush; });
    BOOST_CHECK_EQUAL(vars.count, 1u);
  }
  // 1 -> 2
  {
    fuzzuf::utils::DumpTracer tracer(
        [](std::string &&m) { std::cout << m << std::flush; });
    fuzzuf::utils::ElapsedTimeTracer ett;
    wrapped(vars, tracer, ett);
    ett.dump([](std::string &&m) { std::cout << m << std::flush; });
    BOOST_CHECK_EQUAL(vars.count, 2u);
  }
  // 2 -> 2
  {
    fuzzuf::utils::DumpTracer tracer(
        [](std::string &&m) { std::cout << m << std::flush; });
    fuzzuf::utils::ElapsedTimeTracer ett;
    wrapped(vars, tracer, ett);
    ett.dump([](std::string &&m) { std::cout << m << std::flush; });
    BOOST_CHECK_EQUAL(vars.count, 2u);
  }
}

/**
 * HierarFlowのRandomCallで乱数が特定の状態の時に子ノードのEraseBytesとInsertByteのうちInsertByteだけが選ばれて実行される事を確認する
 */
BOOST_AUTO_TEST_CASE(HierarFlowRandomCall0) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  auto data = lf::test::getSeed2();
  using Ord = lf::test::Order;
  auto random =
      hf::CreateNode<lf::standard_order::RandomCall<lf::test::Full, Ord>>();
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR(EraseBytes, erase_bytes);
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR(InsertByte, insert_byte);
  random << (erase_bytes || insert_byte);
  lf::test::Variables vars;
  vars.rng.seed(9U);
  std::copy(data.begin(), data.end(), std::back_inserter(vars.input[0]));
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(random)(vars, tracer, ett);
  data.clear();
  std::copy(vars.input[0].begin(), vars.input[0].end(),
            std::back_inserter(data));
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  const std::vector<std::uint8_t> expected1{
      'j', 'u', 'm', 'p', 's', ' ', 'o',   'v', 'e', 'r', ' ', 't',
      'h', 'e', ' ', 'l', 'a', 'z', 0x8bU, 'y', ' ', 'd', 'o', 'g'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
}

/**
 * HierarFlowのRandomCallで乱数が特定の状態の時に子ノードのEraseBytesとInsertByteのうちEraseBytesだけが選ばれて実行される事を確認する
 */
BOOST_AUTO_TEST_CASE(HierarFlowRandomCall1) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  auto data = lf::test::getSeed2();
  using Ord = lf::test::Order;
  auto random =
      hf::CreateNode<lf::standard_order::RandomCall<lf::test::Full, Ord>>();
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR(EraseBytes, erase_bytes);
  FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR(InsertByte, insert_byte);
  random << (erase_bytes || insert_byte);
  lf::test::Variables vars;
  vars.rng.seed(2U);
  std::copy(data.begin(), data.end(), std::back_inserter(vars.input[0]));
  fuzzuf::utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  fuzzuf::utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(random)(vars, tracer, ett);
  data.clear();
  std::copy(vars.input[0].begin(), vars.input[0].end(),
            std::back_inserter(data));
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
  const std::vector<std::uint8_t> expected1{'j', 'u', 'm', 'p', 's', ' ',
                                            'o', 'v', 'e', 'r', ' ', 'z',
                                            'y', ' ', 'd', 'o', 'g'};
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected1.begin(),
                                expected1.end());
}
