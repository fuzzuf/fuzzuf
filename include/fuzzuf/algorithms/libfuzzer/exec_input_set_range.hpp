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
 * @file exec_input_set_range.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXEC_INPUT_SET_RANGE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXEC_INPUT_SET_RANGE_HPP
#include <boost/range/iterator_range.hpp>
#include <cctype>
#include <type_traits>

#include "fuzzuf/exec_input/exec_input_set.hpp"

namespace fuzzuf::algorithm::libfuzzer {

#define FUZZUF_ALGORITHM_LIBFUZZER_EXEC_INPUT_SET_RANGE_ITERATOR_OPS     \
  BasicExecInputSetIterator(base_iter_t b, exec_input::ExecInputSet &s)  \
      : base(b), set(s) {}                                               \
                                                                         \
  base_iter_t &get() { return base; }                                    \
  const base_iter_t &get() const { return base; }                        \
                                                                         \
  self_type_t &operator++() {                                            \
    ++base;                                                              \
    return *this;                                                        \
  }                                                                      \
                                                                         \
  self_type_t &operator++(int) {                                         \
    auto old = *this;                                                    \
    base++;                                                              \
    return old;                                                          \
  }                                                                      \
                                                                         \
  bool operator==(const self_type_t &r) const { return base == r.base; } \
                                                                         \
  bool operator!=(const self_type_t &r) const { return base != r.base; } \
                                                                         \
  self_type_t &operator--() {                                            \
    --base;                                                              \
    return *this;                                                        \
  }                                                                      \
                                                                         \
  self_type_t operator--(int) {                                          \
    auto old = *this;                                                    \
    base--;                                                              \
    return old;                                                          \
  }                                                                      \
                                                                         \
  self_type_t &operator+=(difference_type n) {                           \
    base += n;                                                           \
    return *this;                                                        \
  }                                                                      \
                                                                         \
  self_type_t &operator-=(difference_type n) {                           \
    base -= n;                                                           \
    return *this;                                                        \
  }                                                                      \
                                                                         \
  self_type_t operator+(difference_type n) const {                       \
    return self_type_t(base + n, set);                                   \
  }                                                                      \
                                                                         \
  self_type_t operator-(difference_type n) const {                       \
    return self_type_t(base - n, set);                                   \
  }                                                                      \
                                                                         \
  difference_type operator-(const self_type_t &r) const {                \
    return base - r.base;                                                \
  }                                                                      \
                                                                         \
 private:                                                                \
  base_iter_t base;                                                      \
  exec_input::ExecInputSet &set;

/**
 * @class BasicExecInputSetIterator
 * C++ Random access iterator compliant adaptor to traverse ExecInputSet
 * elements.
 * @tparam unwrap
 * If true, dereferenced value is range of std::uint8_t.
 * Otherwise, dereferenced value is reference to ExecInput.
 * @tparam Reference Reference type to an element.
 */
template <bool unwrap, typename Reference>
class BasicExecInputSetIterator {};
template <typename Reference>
class BasicExecInputSetIterator<false, Reference> {
  using self_type_t = BasicExecInputSetIterator<false, Reference>;

 public:
  using iterator_category = std::random_access_iterator_tag;
  using reference = Reference;
  using value_type = exec_input::ExecInput;
  using base_iter_t = std::vector<std::uint64_t>::iterator;
  using difference_type =
      decltype(std::declval<base_iter_t>() - std::declval<base_iter_t>());
  using pointer = void;

  reference operator*() const { return *set.get_ref(*base); }

  reference operator[](difference_type n) const {
    return *set.get_ref(base[n]);
  }

  FUZZUF_ALGORITHM_LIBFUZZER_EXEC_INPUT_SET_RANGE_ITERATOR_OPS
};

template <typename Reference>
class BasicExecInputSetIterator<true, Reference> {
  using self_type_t = BasicExecInputSetIterator<true, Reference>;

 public:
  using iterator_category = std::input_iterator_tag;
  using value_type = boost::iterator_range<std::uint8_t *>;
  using reference = value_type;
  using base_iter_t = std::vector<std::uint64_t>::iterator;
  using difference_type =
      decltype(std::declval<base_iter_t>() - std::declval<base_iter_t>());
  using pointer = void;

  reference operator*() const {
    auto &exec_input = set.get_ref(*base)->get();
    return value_type(exec_input.GetBuf(),
                      std::next(exec_input.GetBuf(), exec_input.GetLen()));
  }

  reference operator[](difference_type n) const {
    auto &exec_input = set.get_ref(base[n])->get();
    return value_type(exec_input.GetBuf(),
                      std::next(exec_input.GetBuf(), exec_input.GetLen()));
  }

  FUZZUF_ALGORITHM_LIBFUZZER_EXEC_INPUT_SET_RANGE_ITERATOR_OPS
};

template <bool unwrap>
using ExecInputSetIterator =
    BasicExecInputSetIterator<unwrap, exec_input::ExecInput &>;
template <bool unwrap>
using ConstExecInputSetIterator =
    BasicExecInputSetIterator<unwrap, const exec_input::ExecInput &>;

/**
 * @enum ExecInputSetRangeInsertMode
 * Enums to indicate behaviour of insertion to ExecInputSetRange
 */
enum class ExecInputSetRangeInsertMode {
  NONE,       // insert() is not available
  IN_MEMORY,  // insert() causes inserting value using CreateOnMemory()
  ON_DISK     // insert() causes inserting value using CreateOnDisk()
};

/**
 * @class ExecInputSetRange
 * A range adaptor to make ExecInputSet to C++ range compliant.
 * @tparam unwrap
 * If true, dereferenced value is range of std::uint8_t.
 * Otherwise, dereferenced value is reference to ExecInput.
 * @tparam mode Specify how to insert value.
 */
template <bool unwrap, ExecInputSetRangeInsertMode mode>
class ExecInputSetRange {
 public:
  using value_type = typename ExecInputSetIterator<unwrap>::value_type;
  using reference = typename ExecInputSetIterator<unwrap>::reference;
  using const_reference = const reference;
  using size_type = std::size_t;
  using difference_type =
      typename ExecInputSetIterator<unwrap>::difference_type;
  using iterator = ExecInputSetIterator<unwrap>;
  using const_iterator = ConstExecInputSetIterator<unwrap>;
  ExecInputSetRange(exec_input::ExecInputSet &s) : set(s) {
    auto ids_ = set.get_ids();
    ids.reset(new std::vector<std::uint64_t>(ids_.begin(), ids_.end()));
  }
  iterator begin() { return iterator(ids->begin(), set); }
  const_iterator begin() const { return const_iterator(ids->begin(), set); }
  const_iterator cbegin() const { return const_iterator(ids->begin(), set); }
  iterator end() { return iterator(ids->end(), set); }
  const_iterator end() const { return const_iterator(ids->end(), set); }
  const_iterator cend() const { return const_iterator(ids->end(), set); }
  size_type size() const { return ids->size(); }
  bool empty() const { return ids->empty(); }
  template <ExecInputSetRangeInsertMode mode_ = mode, typename... Args>
  auto emplace(Args &&...args)
      -> std::enable_if_t<mode_ != ExecInputSetRangeInsertMode::NONE,
                          std::pair<iterator, bool>> {
    if constexpr (mode == ExecInputSetRangeInsertMode::IN_MEMORY) {
      exec_input::OnMemoryExecInput elem(std::move(args)...);
      const auto id = elem.GetID();
      const auto existing =
          std::find(set.get_ids().begin(), set.get_ids().end(), id) !=
          set.get_ids().end();
      set.CreateOnMemory(std::move(elem));
      auto created = std::find(set.get_ids().begin(), set.get_ids().end(), id);
      auto ids_ = set.get_ids();
      ids.reset(new std::vector<std::uint64_t>(ids_.begin(), ids_.end()));
      return std::make_pair(iterator(created, set), existing);
    } else if constexpr (mode == ExecInputSetRangeInsertMode::ON_DISK) {
      exec_input::OnDiskExecInput elem(std::move(args)...);
      const auto id = elem.GetID();
      const auto existing =
          std::find(set.get_ids().begin(), set.get_ids().end(), id) !=
          set.get_ids().end();
      set.CreateOnDisk(std::move(elem));
      auto created = std::find(set.get_ids().begin(), set.get_ids().end(), id);
      auto ids_ = set.get_ids();
      ids.reset(new std::vector<std::uint64_t>(ids_.begin(), ids_.end()));
      return std::make_pair(iterator(created, set), existing);
    } else {
      static_assert(mode == ExecInputSetRangeInsertMode::ON_DISK);
    }
  }
  void erase(iterator pos) {
    set.erase(*pos.get());
    auto ids_ = set.get_ids();
    ids.reset(new std::vector<std::uint64_t>(ids_.begin(), ids_.end()));
  }
  void erase(const_iterator pos) {
    set.erase(*pos.get());
    auto ids_ = set.get_ids();
    ids.reset(new std::vector<std::uint64_t>(ids_.begin(), ids_.end()));
  }
  reference operator[](int pos) { return *set.get_ref((*ids)[pos]); }
  const_reference operator[](int pos) const {
    return *set.get_ref((*ids)[pos]);
  }
  reference at(int pos) {
    if (pos < 0 || pos >= size())
      throw std::out_of_range("ExecInputSetRange: out of range");
    return operator[](pos);
  }
  const_reference at(int pos) const {
    if (pos < 0 || pos >= size())
      throw std::out_of_range("ExecInputSetRange: out of range");
    return operator[](pos);
  }

 private:
  exec_input::ExecInputSet &set;
  std::shared_ptr<std::vector<std::uint64_t>> ids;
};

namespace adaptor {
template <bool unwrap, ExecInputSetRangeInsertMode mode>
struct ExecInputSetRangeT {};
template <bool unwrap, ExecInputSetRangeInsertMode mode>
constexpr auto exec_input_set_range = ExecInputSetRangeT<unwrap, mode>();

/**
 * Create ExecInputSetRange
 *
 * @tparam T base range type
 * @tparam unwrap If ture, dereferenced value is range of std::uint8_t.
 * Otherwise, dereferenced value is reference to ExecInput.
 * @tparam mode Specify how to insert value.
 * @param p base range
 * @return p piped to ExecInputSetRange
 */
template <typename T, bool unwrap, ExecInputSetRangeInsertMode mode>
auto operator|(T &p, const ExecInputSetRangeT<unwrap, mode> &)
    -> decltype(fuzzuf::algorithm::libfuzzer::ExecInputSetRange<unwrap, mode>(
        std::declval<T &>())) {
  return fuzzuf::algorithm::libfuzzer::ExecInputSetRange<unwrap, mode>(p);
}
}  // namespace adaptor

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
