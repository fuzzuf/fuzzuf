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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_CORPUS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_CORPUS_HPP
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>
#include <cstddef>
#include <string>
#include <vector>

namespace fuzzuf::algorithm::libfuzzer {

struct Sequential {};
struct ByName {};
struct ById {};

// libFuzzerはtestcaseの並び順を利用する為、corpusは並び順を覚えられるコンテナでなければならない
using PartialCorpus = boost::multi_index::multi_index_container<
    InputInfo,
    boost::multi_index::indexed_by<
        boost::multi_index::sequenced<boost::multi_index::tag<Sequential>>,
        boost::multi_index::hashed_non_unique<
            boost::multi_index::tag<ByName>,
            boost::multi_index::member<InputInfo, std::string,
                                       &InputInfo::name>>,
        boost::multi_index::hashed_unique<
            boost::multi_index::tag<ById>,
            boost::multi_index::member<InputInfo, testcase_id_t,
                                       &InputInfo::id>>>>;

/**
 * @class is_partial_corpus
 * @brief 与えられた型TがPartialCorpus型の要件を満たす場合にtrueを返すメタ関数
 *
 * @tparm T 任意の型
 */
template <typename T, typename Enable = void>
struct is_partial_corpus : public std::false_type {};
template <typename T>
struct is_partial_corpus<
    T, std::enable_if_t<
           is_input_info_v<utils::type_traits::RemoveCvrT<decltype(
               *std::declval<T &>().template get<Sequential>().begin())>> &&
           is_input_info_v<utils::type_traits::RemoveCvrT<decltype(
               *std::declval<T &>().template get<ByName>().begin())>> &&
           is_input_info_v<utils::type_traits::RemoveCvrT<decltype(
               *std::declval<T &>().template get<ById>().begin())>>>>
    : public std::true_type {};
template <typename T>
constexpr bool is_partial_corpus_v = is_partial_corpus<T>::value;

/**
 * @class FullCorpus
 * 入力値のコンテナと入力値以外の実行結果の詳細のコンテナを合わせたもの
 */
struct FullCorpus {
  // 保存されている入力値
  ExecInputSet inputs;
  // 保存されている入力値に付随する情報
  PartialCorpus corpus;
};

/**
 * @class is_full_corpus
 * @brief 与えられた型TがFullCorpus型の要件を満たす場合にtrueを返すメタ関数
 *
 * @tparm T 任意の型
 */
template <typename T, typename Enable = void>
struct is_full_corpus : public std::false_type {};
template <typename T>
struct is_full_corpus<
    T, std::enable_if_t<is_partial_corpus_v<utils::type_traits::RemoveCvrT<
                            decltype(std::declval<T &>().corpus)>> &&
                        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                                           std::declval<T &>().inputs)>,
                                       ExecInputSet>>> : public std::true_type {
};
template <typename T>
constexpr bool is_full_corpus_v = is_full_corpus<T>::value;

/**
 * @fn
 * PartialCorpusを文字列に変換する
 * @param dest 出力先
 * @param value 値
 * @param index_count インデントの深さ
 * @param indent インデントに使う文字列
 */
bool toString(std::string &dest, const PartialCorpus &value,
              std::size_t indent_count, const std::string &indent);

/**
 * @fn
 * FullCorpusを文字列に変換する
 * @param dest 出力先
 * @param value 値
 * @param index_count インデントの深さ
 * @param indent インデントに使う文字列
 */
bool toString(std::string &dest, const FullCorpus &value,
              std::size_t indent_count, const std::string &indent);

} // namespace fuzzuf::algorithm::libfuzzer

#endif
