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
/**
 * @file corpus.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_CORPUS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_CORPUS_HPP
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>
#include <cstddef>
#include <string>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"

namespace fuzzuf::algorithm::libfuzzer {

struct Sequential {};
struct ByName {};
struct ById {};

/**
 * Since libFuzzer uses insertion order, corpus must provide both sequential
 * index and hashed index.
 */
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
 * @brief Meta function to check if the type satisfies PartialCorpus concept
 *
 * @tparam T Type to check
 */
template <typename T, typename Enable = void>
struct is_partial_corpus : public std::false_type {};
template <typename T>
struct is_partial_corpus<
    T,
    std::enable_if_t<
        is_input_info_v<utils::type_traits::RemoveCvrT<
            decltype(*std::declval<T &>()
                          .template get<Sequential>()
                          .begin())>> &&
        is_input_info_v<utils::type_traits::RemoveCvrT<
            decltype(*std::declval<T &>().template get<ByName>().begin())>> &&
        is_input_info_v<utils::type_traits::RemoveCvrT<
            decltype(*std::declval<T &>().template get<ById>().begin())>>>>
    : public std::true_type {};
template <typename T>
constexpr bool is_partial_corpus_v = is_partial_corpus<T>::value;

/**
 * @class FullCorpus
 * Pair of container to store input values and container to store execution
 * results
 */
struct FullCorpus {
  // container to store input values
  exec_input::ExecInputSet inputs;
  // container to store execution results
  PartialCorpus corpus;
};

/**
 * @class is_full_corpus
 * @brief Meta function to check if the type satisfies FullCorpus concept
 *
 * @tparam T Type to check
 */
template <typename T, typename Enable = void>
struct is_full_corpus : public std::false_type {};
template <typename T>
struct is_full_corpus<
    T,
    std::enable_if_t<is_partial_corpus_v<utils::type_traits::RemoveCvrT<
                         decltype(std::declval<T &>().corpus)>> &&
                     std::is_same_v<utils::type_traits::RemoveCvrT<
                                        decltype(std::declval<T &>().inputs)>,
                                    exec_input::ExecInputSet>>>
    : public std::true_type {};
template <typename T>
constexpr bool is_full_corpus_v = is_full_corpus<T>::value;

/**
 * Serialize PartialCorpus into string
 * @param dest Serialized string is stored in this value
 * @param value Partial corpus to serialize
 * @param index_count Initial indentation depth
 * @param indent String to insert for indentation
 */
bool toString(std::string &dest, const PartialCorpus &value,
              std::size_t indent_count, const std::string &indent);

/**
 * Serialize FullCorpus into string
 * @param dest Serialized string is stored in this value
 * @param value Full corpus to serialize
 * @param index_count Initial indentation depth
 * @param indent String to insert for indentation
 */
bool toString(std::string &dest, const FullCorpus &value,
              std::size_t indent_count, const std::string &indent);

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
