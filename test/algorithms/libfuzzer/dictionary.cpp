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
#define BOOST_TEST_MODULE algorithms.libfuzzer.dictionary
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/algorithms/libfuzzer/dictionary.hpp"

#include <config.h>

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <system_error>

#include "fuzzuf/exceptions.hpp"

// テスト用の辞書からレベル0(デフォルト)以上(==全ての要素)の内容を正しく読める事を確認する
// 辞書のエントリのkeyが 名前, '@', { 数値 }
// という形になっている場合、そのエントリはレベル指定付きエントリになる
// ロード時に最低レベルが指定された場合、レベル指定付きエントリのうち指定されたレベルより低いレベルのものはロードされなくなる
// 詳しくはAFLの辞書の説明(
// https://github.com/mirrorer/afl/blob/master/dictionaries/README.dictionaries
// )
BOOST_AUTO_TEST_CASE(LoadDictionary) {
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;
  Load(TEST_DICTIONARY_DIR "/test.dict", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary expected{
      {{'h', 'o', 'g', 'e'}},
      {{'a', 0x03, 'b', 0x91, 'c'}},
      {{'f', 'u', 'g', 'a'}}};
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
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;
  Load(TEST_DICTIONARY_DIR "/test.dict@1", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary expected{
      {{'h', 'o', 'g', 'e'}},
      {{'a', 0x03, 'b', 0x91, 'c'}},
      {{'f', 'u', 'g', 'a'}}};
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
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;
  Load(TEST_DICTIONARY_DIR "/test.dict@2", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary expected{
      {{'h', 'o', 'g', 'e'}}, {{'a', 0x03, 'b', 0x91, 'c'}}};
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected.begin(),
                                expected.end());
}

// 1つのStaticDictionary型の変数に対して辞書を複数読んだ場合に、読んだ順に全ての辞書の要素が並ぶ事を確認する
BOOST_AUTO_TEST_CASE(LoadMultipleDictionaries) {
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;
  Load(TEST_DICTIONARY_DIR "/test.dict@2", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });
  Load(TEST_DICTIONARY_DIR "/test.dict@1", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary expected{
      {{'h', 'o', 'g', 'e'}},
      {{'a', 0x03, 'b', 0x91, 'c'}},
      {{'h', 'o', 'g', 'e'}},
      {{'a', 0x03, 'b', 0x91, 'c'}},
      {{'f', 'u', 'g', 'a'}}};
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected.begin(),
                                expected.end());
}

// StaticDictionaryEntry型の値同士の比較演算が正しい値を返す事を確認する
BOOST_AUTO_TEST_CASE(CompareDictinaryEntries) {
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionaryEntry n1{
      {'h', 'o', 'g', 'e'}};
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionaryEntry n2{
      {'h', 'o', 'g', 'e'}};
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionaryEntry n3{
      {'h', 'o', 'g', 'e'}, 5};
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionaryEntry n4{
      {'h', 'o', 'g', 'e'}};
  n4.increment_use_count();
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionaryEntry n5{
      {'h', 'o', 'g', 'e'}};
  n5.increment_success_count();
  BOOST_CHECK_EQUAL(n1, n2);
  BOOST_CHECK(n1 != n3);
  BOOST_CHECK(n1 != n4);
  BOOST_CHECK(n1 != n5);
}

// 存在しない辞書を読もうとした場合にstd::system_error例外が飛ぶ事を確認する
BOOST_AUTO_TEST_CASE(DictionaryNotFound) {
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/non_exists.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    std::system_error);
}
// 破損した辞書を読もうとした場合にinvalid_file例外が飛ぶ事を確認する
BOOST_AUTO_TEST_CASE(CorruptedDictionary) {
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;

  // "が閉じていない
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/corrupted.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // keyしかない
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/corrupted2.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // valueの後ろにコメント以外の文字がある
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/corrupted3.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // keyが空文字列
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/corrupted4.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // エスケープシーケンスが途中で途切れている
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/corrupted5.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // エスケープシーケンスが途中で途切れている
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/corrupted6.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  // エスケープシーケンスが途中で途切れている
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/corrupted7.dict", dict, false,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);
}

// 空の辞書を読むと読み込みが成功し何も追加されない事を確認する
BOOST_AUTO_TEST_CASE(EmptyDictionary) {
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;
  Load(TEST_DICTIONARY_DIR "/empty.dict", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary expected;
  BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected.begin(),
                                expected.end());
}

// テスト用の辞書(strict)がstrictモードで読めて、テスト用辞書(relaxed)がstrictモードで読めない事を確認する
BOOST_AUTO_TEST_CASE(StrictMode) {
  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;
  Load(TEST_DICTIONARY_DIR "/test.dict", dict, true,
       [](std::string &&m) { std::cerr << m << std::endl; });

  {
    std::unique_ptr<fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary>
        expected(new fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary{
            {{'h', 'o', 'g', 'e'}},
            {{'a', 0x03, 'b', 0x91, 'c'}},
            {{'f', 'u', 'g', 'a'}}});
    BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected->begin(),
                                  expected->end());
  }

  dict.clear();
  BOOST_CHECK_THROW(Load(TEST_DICTIONARY_DIR "/relaxed.dict", dict, true,
                         [](std::string &&m) { std::cerr << m << std::endl; }),
                    fuzzuf::exceptions::invalid_file);

  Load(TEST_DICTIONARY_DIR "/relaxed.dict", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });
  {
    std::unique_ptr<fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary>
        expected(new fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary{
            {{0xe3, 0x81, 0x82, 0xe3, 0x81, 0x84, 0xe3, 0x81, 0x86}},
            {{'a', 0x03, 'b', 0x91, 'c'}},
            {{0xe3, 0x81, 0x88, 0x0a, 0xe3, 0x81, 0x8a}}});
    BOOST_CHECK_EQUAL_COLLECTIONS(dict.begin(), dict.end(), expected->begin(),
                                  expected->end());
  }
}
