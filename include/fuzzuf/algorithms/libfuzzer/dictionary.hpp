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
 * @file dictionary.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_DICTIONARY_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_DICTIONARY_HPP
#include <algorithm>
#include <boost/container/static_vector.hpp>
#include <cstddef>
#include <functional>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/range_traits.hpp"

namespace fuzzuf::algorithm::libfuzzer::dictionary {
template <typename Word>
class BasicDictionaryEntry {
 public:
  using word_t = Word;

  BasicDictionaryEntry() {}

  BasicDictionaryEntry(const word_t &w) : word(w) {
    hash = std::hash<std::string_view>()(std::string_view(
        reinterpret_cast<const char *>(&*w.begin()), w.size()));
  }

  BasicDictionaryEntry(const word_t &w, std::size_t ph)
      : word(w), position_hint(ph) {
    hash = std::hash<std::string_view>()(std::string_view(
        reinterpret_cast<const char *>(&*w.begin()), w.size()));
  }

  const word_t &get() const { return word; }

  std::size_t get_hash() const { return hash; }

  bool has_position_hint() const {
    return position_hint != std::numeric_limits<std::size_t>::max();
  }

  std::size_t get_position_hint() const { return position_hint; }

  void increment_use_count() { ++use_count; }

  void increment_success_count() { ++success_count; }

  std::size_t get_use_count() const { return use_count; }

  std::size_t get_success_count() const { return success_count; }

  void reset_use_count() {
    use_count = 0u;
    success_count = 0u;
  }

  bool operator==(const BasicDictionaryEntry &r) const {
    return std::equal(word.begin(), word.end(), r.word.begin(), r.word.end()) &&
           position_hint == r.position_hint && use_count == r.use_count &&
           success_count == r.success_count;
  }

  bool operator!=(const BasicDictionaryEntry &r) const {
    return !std::equal(word.begin(), word.end(), r.word.begin(),
                       r.word.end()) ||
           position_hint != r.position_hint || use_count != r.use_count ||
           success_count != r.success_count;
  }

  nlohmann::json to_json() const {
    auto root = nlohmann::json::object();
    root["word"] = nlohmann::json::array();
    for (const auto &v : word) root["word"].push_back(v);
    root["position_hint"] = position_hint;
    root["use_count"] = use_count;
    root["success_count"] = success_count;
    return root;
  }

 private:
  word_t word;
  std::size_t position_hint = std::numeric_limits<std::size_t>::max();
  // How many times the value was choosed
  std::size_t use_count = 0u;
  // How many times the value caused to find new coverage
  std::size_t success_count = 0u;
  std::size_t hash = 0u;
};

template <typename Word>
bool toString(std::string &dest, const BasicDictionaryEntry<Word> &value) {
  try {
    dest += value.to_json().dump();
    return true;
  } catch (...) {
    return false;
  }
}

template <typename Word>
std::size_t GetPositionHint(const BasicDictionaryEntry<Word> &v) {
  return v.GetPositionHint();
}

template <typename Traits, typename T>
std::basic_ostream<char, Traits> &operator<<(
    std::basic_ostream<char, Traits> &l, const BasicDictionaryEntry<T> &r) {
  l << r.to_json().dump();
  return l;
}

/**
 * Static dictionary uses static_vector for both container to store byte
 * sequence and container to store dictionary entries. Static dictionary has
 * much closer behaviour to original libFuzzer implementation and it has same
 * size limitation.
 */
using StaticDictionaryEntry =
    BasicDictionaryEntry<boost::container::static_vector<std::uint8_t, 64u>>;
using StaticDictionary =
    boost::container::static_vector<StaticDictionaryEntry, 1u << 14>;

template <typename Traits>
std::basic_ostream<char, Traits> &operator<<(
    std::basic_ostream<char, Traits> &l, const StaticDictionary &r) {
  auto root = nlohmann::json::array();
  for (auto &v : r) root.push_back(v.to_json());
  l << root.dump();
  return l;
}

/**
 * Dynamic dictionary uses vector for the continers.
 * Dynamic dictionary may allocate memory during fuzzing, but the size
 * limitation is much looser.
 */
using DynamicDictionaryEntry = BasicDictionaryEntry<std::vector<uint8_t>>;
using DynamicDictionary = std::vector<DynamicDictionaryEntry>;

template <typename Traits>
std::basic_ostream<char, Traits> &operator<<(
    std::basic_ostream<char, Traits> &l, const DynamicDictionary &r) {
  auto root = nlohmann::json::array();
  for (auto &v : r) root.push_back(v.to_json());
  l << root.dump();
  return l;
}

void Load(const std::string &filename, StaticDictionary &, bool strict,
          const std::function<void(std::string &&)> &eout);

void Load(const std::string &filename, DynamicDictionary &, bool strict,
          const std::function<void(std::string &&)> &eout);

void Load(const std::vector<fs::path> &paths, StaticDictionary &dest,
          bool strict, const std::function<void(std::string &&)> &eout);

void Load(const std::vector<fs::path> &paths, DynamicDictionary &dest,
          bool strict, const std::function<void(std::string &&)> &eout);

template <typename T>
struct IsDictionaryEntry : public std::false_type {};
template <typename T>
struct IsDictionaryEntry<BasicDictionaryEntry<T>> : public std::true_type {};
template <typename T>
constexpr bool is_dictionary_entry_v = IsDictionaryEntry<T>::value;

template <typename T, typename Enable = void>
struct IsDictionary : public std::false_type {};
template <typename T>
struct IsDictionary<
    T, std::enable_if_t<is_dictionary_entry_v<utils::range::RangeValueT<T>>>>
    : public std::true_type {};
template <typename T>
constexpr bool is_dictionary_v = IsDictionary<T>::value;

template <typename T, typename Enable = void>
struct WordType {};
template <typename T>
struct WordType<T, std::enable_if_t<is_dictionary_entry_v<T>>> {
  using type = typename T::word_t;
};
template <typename T>
struct WordType<T, std::enable_if_t<is_dictionary_v<T>>> {
  using type = typename WordType<utils::range::RangeValueT<T>>::type;
};
template <typename T>
using WordTypeT = typename WordType<T>::type;

template <typename Dict>
using DictionaryHistory = std::vector<utils::range::RangeValueT<Dict> *>;
}  // namespace fuzzuf::algorithm::libfuzzer::dictionary
#endif
