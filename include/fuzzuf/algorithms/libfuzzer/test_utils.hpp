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
#ifndef FUZZUF_INCLUDE_ALGORITHMS_LIBFUZZER_TEST_UTILS_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_LIBFUZZER_TEST_UTILS_HPP
#include "fuzzuf/algorithms/libfuzzer/dictionary.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/common_types.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/utils/detect_copy.hpp"
#include "fuzzuf/utils/node_tracer.hpp"
#include "fuzzuf/utils/not_random.hpp"
#include <chrono>
#include <cstdint>
#include <vector>

// テストを書くときに頻繁に書くことになるコードをまとめた物
namespace fuzzuf::algorithm::libfuzzer::test {

/*
 * テスト用のState
 * 乱数生成器がランダムでない値を返すようになっている
 */

using RNG = fuzzuf::utils::not_random::Sequential<unsigned int>;
using Dict = fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary;
using Range = utils::DetectCopy<std::vector<std::uint8_t>>;
using Ranges = std::array<Range, 3u>; // { input, crossover, mask }
using State = fuzzuf::algorithm::libfuzzer::State;
using ElapsedTimeClock = std::chrono::system_clock::time_point;
using DictHistory = dictionary::DictionaryHistory<Dict>;
/*
 * テスト用の入力値
 */
auto getSeed1() -> Range;
auto getSeed2() -> Range;

/*
 * test.dictの内容をmanual_dictにロードする
 */
void LoadDictionary(
    fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary &dict);

struct Variables {
  State state;
  FullCorpus corpus;
  std::minstd_rand rng;
  Ranges input;
  std::size_t max_input_size = 40000u;
  MutationHistory mutation_history;
  Dict persistent_auto_dict;
  DictHistory dict_history;
  InputInfo exec_result;
  coverage_t coverage;
  std::size_t count = 0u;
  ElapsedTimeClock begin_date;
  std::size_t last_corpus_update_run = 0u;
};

// fuzzer全体を動かすのに必要な引数を持つ型
using Full = bool(Variables &, utils::DumpTracer &, utils::ElapsedTimeTracer &);

namespace sp = utils::struct_path;
struct Order {
  using V = Variables;
  constexpr static auto arg0 = sp::root / sp::arg<0>;
  constexpr static auto state = arg0 / sp::mem<V, State, &V::state>;
  constexpr static auto corpus = arg0 / sp::mem<V, FullCorpus, &V::corpus>;
  constexpr static auto rng = arg0 / sp::mem<V, std::minstd_rand, &V::rng>;
  constexpr static auto input =
      arg0 / sp::mem<V, Ranges, &V::input> / sp::elem<0u>;
  constexpr static auto max_length =
      arg0 / sp::mem<V, std::size_t, &V::max_input_size>;
  constexpr static auto mutation_history =
      arg0 / sp::mem<V, MutationHistory, &V::mutation_history>;
  constexpr static auto crossover =
      arg0 / sp::mem<V, Ranges, &V::input> / sp::elem<1u>;
  constexpr static auto dict =
      arg0 / sp::mem<V, Dict, &V::persistent_auto_dict>;
  constexpr static auto dict_history =
      arg0 / sp::mem<V, DictHistory, &V::dict_history>;
  constexpr static auto exec_result =
      arg0 / sp::mem<V, InputInfo, &V::exec_result>;
  constexpr static auto coverage = arg0 / sp::mem<V, coverage_t, &V::coverage>;
  constexpr static auto output = sp::root / sp::ident<output_t>;
  constexpr static auto count = arg0 / sp::mem<V, std::size_t, &V::count>;
  constexpr static auto begin_date =
      arg0 / sp::mem<V, ElapsedTimeClock, &V::begin_date>;
  constexpr static auto mask =
      arg0 / sp::mem<V, Ranges, &V::input> / sp::elem<2u>;
  constexpr static auto last_corpus_update_run =
      arg0 / sp::mem<V, std::size_t, &V::last_corpus_update_run>;
};
using MutationPaths = decltype(Order::rng && Order::input &&
                               Order::max_length && Order::mutation_history);

/*
 * ノードLを単品で実行する
 */
template <template <typename...> typename L, typename Input>
void run_hierarflow(Input &data) {
  fuzzuf::algorithm::libfuzzer::State state;
  auto node = fuzzuf::hierarflow::CreateNode<L<Full, MutationPaths>>();
  Variables v;
  std::copy(data.begin(), data.end(), std::back_inserter(v.input[0]));
  utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(node)(v, tracer, ett);
  data.clear();
  std::copy(v.input[0].begin(), v.input[0].end(), std::back_inserter(data));
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
}

/*
 * ノードLを2つ || で繋いだ状態のものを実行する
 */
template <template <typename...> typename L, typename Input>
void run_hierarflow_logical_or(Input &data) {
  auto node1 = fuzzuf::hierarflow::CreateNode<L<Full, MutationPaths>>();
  auto node2 = fuzzuf::hierarflow::CreateNode<L<Full, MutationPaths>>();
  auto nop = fuzzuf::hierarflow::CreateNode<Proxy<Full>>();
  nop << (node1 || node2);
  Variables v;
  std::copy(data.begin(), data.end(), std::back_inserter(v.input[0]));
  utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(nop)(v, tracer, ett);
  data.clear();
  std::copy(v.input[0].begin(), v.input[0].end(), std::back_inserter(data));
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
}

/*
 * ノードLを2つ << で繋いだ状態のものを実行する
 */
template <template <typename...> typename L, typename Input>
void run_hierarflow_shift_left(Input &data) {
  auto node1 = fuzzuf::hierarflow::CreateNode<L<Full, MutationPaths>>();
  auto node2 = fuzzuf::hierarflow::CreateNode<L<Full, MutationPaths>>();
  node1 << node2;
  Variables v;
  std::copy(data.begin(), data.end(), std::back_inserter(v.input[0]));
  utils::DumpTracer tracer(
      [](std::string &&m) { std::cout << m << std::flush; });
  utils::ElapsedTimeTracer ett;
  fuzzuf::hierarflow::WrapToMakeHeadNode(node1)(v, tracer, ett);
  data.clear();
  std::copy(v.input[0].begin(), v.input[0].end(), std::back_inserter(data));
  ett.dump([](std::string &&m) { std::cout << m << std::flush; });
}
/*
 * HierarFlowのノードにする前の生のmutatorを直接実行する
 */
template <typename Func, typename Input>
void run_direct(Func func, Input &data) {
  MutationHistory history;
  std::minstd_rand rng;
  func(rng, data, 40000u, history);
}
/*
 * HierarFlowのノードにする前の生のmutatorを直接2回実行する
 */
template <typename Func, typename Input>
void run_direct_twice(Func func, Input &data) {
  MutationHistory history;
  std::minstd_rand rng;
  func(rng, data, 40000u, history);
  func(rng, data, 40000u, history);
}

} // namespace fuzzuf::algorithm::libfuzzer::test

#define FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW(camel_name, node_name)      \
  auto data = fuzzuf::algorithm::libfuzzer::test::getSeed1();                  \
  fuzzuf::algorithm::libfuzzer::test::run_hierarflow<                          \
      fuzzuf::algorithm::libfuzzer::camel_name>(data);                         \
  auto expected = fuzzuf::algorithm::libfuzzer::test::getSeed1();              \
  fuzzuf::algorithm::libfuzzer::test::run_direct(                              \
      fuzzuf::algorithm::libfuzzer::mutator::node_name<                        \
          std::minstd_rand, fuzzuf::algorithm::libfuzzer::test::Range>,        \
      expected);                                                               \
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),    \
                                expected.end());

#define FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_LOGICAL_OR(camel_name,      \
                                                              node_name)       \
  auto data = fuzzuf::algorithm::libfuzzer::test::getSeed1();                  \
  fuzzuf::algorithm::libfuzzer::test::run_hierarflow_logical_or<               \
      fuzzuf::algorithm::libfuzzer::camel_name>(data);                         \
  auto expected = fuzzuf::algorithm::libfuzzer::test::getSeed1();              \
  fuzzuf::algorithm::libfuzzer::test::run_direct_twice(                        \
      fuzzuf::algorithm::libfuzzer::mutator::node_name<                        \
          std::minstd_rand, fuzzuf::algorithm::libfuzzer::test::Range>,        \
      expected);                                                               \
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),    \
                                expected.end());

#define FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_SHIFT_LEFT(camel_name,      \
                                                              node_name)       \
  auto data = fuzzuf::algorithm::libfuzzer::test::getSeed1();                  \
  fuzzuf::algorithm::libfuzzer::test::run_hierarflow_shift_left<               \
      fuzzuf::algorithm::libfuzzer::camel_name>(data);                         \
  auto expected = fuzzuf::algorithm::libfuzzer::test::getSeed1();              \
  fuzzuf::algorithm::libfuzzer::test::run_direct_twice(                        \
      fuzzuf::algorithm::libfuzzer::mutator::node_name<                        \
          std::minstd_rand, fuzzuf::algorithm::libfuzzer::test::Range>,        \
      expected);                                                               \
  BOOST_CHECK_EQUAL_COLLECTIONS(data.begin(), data.end(), expected.begin(),    \
                                expected.end());

#define FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_TRIPLE(                     \
    test_name, camel_name, node_name)                                          \
  BOOST_AUTO_TEST_CASE(HierarFlow##test_name){                                 \
      FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW(                              \
          camel_name,                                                          \
          node_name)} BOOST_AUTO_TEST_CASE(HierarFlow##test_name##LogicalOr){  \
      FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_LOGICAL_OR(                   \
          camel_name,                                                          \
          node_name)} BOOST_AUTO_TEST_CASE(HierarFlow##test_name##ShiftLeft) { \
    FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_SHIFT_LEFT(camel_name,          \
                                                          node_name)           \
  }

#define FUZZUF_TEST_ALGORITHM_LIBFUZZER_HIERARFLOW_MUTATOR(camel_name, name)   \
  auto name = fuzzuf::hierarflow::CreateNode<                                  \
      fuzzuf::algorithm::libfuzzer::standard_order::camel_name<                \
          fuzzuf::algorithm::libfuzzer::test::Full,                            \
          fuzzuf::algorithm::libfuzzer::test::Order>>();

#endif
