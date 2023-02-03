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
#define BOOST_TEST_MODULE algorithms.afl.dictionary
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <system_error>

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/exceptions.hpp"

using AFLDictData = fuzzuf::algorithm::afl::dictionary::AFLDictData;
using dict_t = std::vector<AFLDictData>;
namespace fuzzuf::algorithm::afl::dictionary {

bool operator==(const AFLDictData &l, const AFLDictData &r) {
  return std::equal(l.data.begin(), l.data.end(), r.data.begin(), r.data.end());
}

bool operator!=(const AFLDictData &l, const AFLDictData &r) {
  return !std::equal(l.data.begin(), l.data.end(), r.data.begin(),
                     r.data.end());
}

template <typename Traits>
std::basic_ostream<char, Traits> &operator<<(
    std::basic_ostream<char, Traits> &l, const AFLDictData &r) {
  l << nlohmann::json(r.data).dump();
  return l;
}

}  // namespace fuzzuf::algorithm::afl::dictionary

// テスト用の辞書からレベル0(デフォルト)以上(==全ての要素)の内容を正しく読める事を確認する
// 辞書のエントリのkeyが 名前, '@', { 数値 }
// という形になっている場合、そのエントリはレベル指定付きエントリになる
// ロード時に最低レベルが指定された場合、レベル指定付きエントリのうち指定されたレベルより低いレベルのものはロードされなくなる
// 詳しくはAFLの辞書の説明(
// https://github.com/mirrorer/afl/blob/master/dictionaries/README.dictionaries
// )
BOOST_AUTO_TEST_CASE(LoadDictionary) {
  dict_t dict;
  load(TEST_DICTIONARY_DIR "/test.dict", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  dict_t expected(3);
  expected[0].data = {'h', 'o', 'g', 'e'};
  expected[1].data = {'a', 0x03, 'b', 0x91, 'c'};
  expected[2].data = {'f', 'u', 'g', 'a'};
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected.begin(),
                                expected.end());
}

// テスト用の辞書からレベル1以上(==全ての要素)の内容を正しく読める事を確認する
// 辞書のエントリのkeyが 名前, '@', { 数値 }
// という形になっている場合、そのエントリはレベル指定付きエントリになる
// ロード時に最低レベルが指定された場合、レベル指定付きエントリのうち指定されたレベルより低いレベルのものはロードされなくなる
// 詳しくはAFLの辞書の説明(
// https://github.com/mirrorer/afl/blob/master/dictionaries/README.dictionaries
// )
BOOST_AUTO_TEST_CASE(LoadDictionaryAtLevel1) {
  dict_t dict;
  load(TEST_DICTIONARY_DIR "/test.dict@1", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  dict_t expected(3);
  expected[0].data = {'h', 'o', 'g', 'e'};
  expected[1].data = {'a', 0x03, 'b', 0x91, 'c'};
  expected[2].data = {'f', 'u', 'g', 'a'};
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected.begin(),
                                expected.end());
}

// テスト用の辞書からレベル2以上の内容を正しく読める事を確認する
// 辞書のエントリのkeyが 名前, '@', { 数値 }
// という形になっている場合、そのエントリはレベル指定付きエントリになる
// ロード時に最低レベルが指定された場合、レベル指定付きエントリのうち指定されたレベルより低いレベルのものはロードされなくなる
// 詳しくはAFLの辞書の説明(
// https://github.com/mirrorer/afl/blob/master/dictionaries/README.dictionaries
// )
BOOST_AUTO_TEST_CASE(LoadDictionaryAtLeve2) {
  dict_t dict;
  load(TEST_DICTIONARY_DIR "/test.dict@2", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  dict_t expected(2);
  expected[0].data = {'h', 'o', 'g', 'e'};
  expected[1].data = {'a', 0x03, 'b', 0x91, 'c'};
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected.begin(),
                                expected.end());
}

// 1つのdict_t型の変数に対して辞書を複数読んだ場合に、読んだ順に全ての辞書の要素が並ぶ事を確認する
BOOST_AUTO_TEST_CASE(LoadMultipleDictionaries) {
  dict_t dict;
  load(TEST_DICTIONARY_DIR "/test.dict@2", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });
  load(TEST_DICTIONARY_DIR "/test.dict@1", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  dict_t expected(5);
  expected[0].data = {'h', 'o', 'g', 'e'};
  expected[1].data = {'a', 0x03, 'b', 0x91, 'c'};
  expected[2].data = {'h', 'o', 'g', 'e'};
  expected[3].data = {'a', 0x03, 'b', 0x91, 'c'};
  expected[4].data = {'f', 'u', 'g', 'a'};
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected.begin(),
                                expected.end());
}

// 存在しない辞書を読もうとした場合にstd::system_error例外が飛ぶ事を確認する
BOOST_AUTO_TEST_CASE(DictionaryNotFound) {
  dict_t dict;
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/non_exists.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    std::system_error);
}

// 破損した辞書を読もうとした場合にinvalid_file例外が飛ぶ事を確認する
BOOST_AUTO_TEST_CASE(CorruptedDictionary) {
  dict_t dict;

  // "が閉じていない
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/corrupted.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // keyしかない
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/corrupted2.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // valueの後ろにコメント以外の文字がある
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/corrupted3.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // keyが空文字列
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/corrupted4.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // エスケープシーケンスが途中で途切れている
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/corrupted5.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // エスケープシーケンスが途中で途切れている
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/corrupted6.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // エスケープシーケンスが途中で途切れている
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/corrupted7.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);
}

// 空の辞書を読むと読み込みが成功し何も追加されない事を確認する
BOOST_AUTO_TEST_CASE(EmptyDictionary) {
  dict_t dict;
  load(TEST_DICTIONARY_DIR "/empty.dict", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  dict_t expected;
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected.begin(),
                                expected.end());
}

// テスト用の辞書(strict)がstrictモードで読めて、テスト用辞書(relaxed)がstrictモードで読めない事を確認する
BOOST_AUTO_TEST_CASE(StrictMode) {
  dict_t dict;
  load(TEST_DICTIONARY_DIR "/test.dict", dict, true,
       [](std::string &&m) { std::cerr << m << std::endl; });

  dict_t expected1(3);
  expected1[0].data = {'h', 'o', 'g', 'e'};
  expected1[1].data = {'a', 0x03, 'b', 0x91, 'c'};
  expected1[2].data = {'f', 'u', 'g', 'a'};
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected1.begin(),
                                expected1.end());

  dict.clear();
  BOOST_CHECK_THROW(load(TEST_DICTIONARY_DIR "/relaxed.dict", dict, true,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  load(TEST_DICTIONARY_DIR "/relaxed.dict", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  dict_t expected2(3);
  expected2[0].data = {0xe3, 0x81, 0x82, 0xe3, 0x81, 0x84, 0xe3, 0x81, 0x86};
  expected2[1].data = {'a', 0x03, 'b', 0x91, 'c'};
  expected2[2].data = {0xe3, 0x81, 0x88, 0x0a, 0xe3, 0x81, 0x8a};
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected2.begin(),
                                expected2.end());
}
