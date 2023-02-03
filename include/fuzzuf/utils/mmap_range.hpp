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
 * @file mmap_range.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_MMAP_RANGE_HPP
#define FUZZUF_INCLUDE_UTILS_MMAP_RANGE_HPP
#include <boost/range/iterator_range.hpp>
#include <memory>
#include <type_traits>

#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::utils::range {

// template <typename T, typename Enable = void>
// class mmap_iterator {};

template <typename T>
class mmap_iterator /*<T,
                    std::enable_if_t<std::is_same_v<
                        typename std::iterator_traits<T>::iterator_category,
                        std::forward_iterator_tag>>>*/
{
 public:
  using iterator_category = std::forward_iterator_tag;
  using base_iter_t = T;
  using difference_type = typename std::iterator_traits<T>::difference_type;
  using value_type = mapped_file_t;
  using pointer = const mapped_file_t *;
  using reference = const value_type &;
  mmap_iterator()
      : flags(0), populate(false), base(base_iter_t()), end(base_iter_t()) {}
  mmap_iterator(const T &base_, const T &end_, unsigned int flags_,
                bool populate_)
      : flags(flags_), populate(populate_), base(base_), end(end_) {
    map();
  }
  reference operator*() const { return cur; }
  base_iter_t &get() { return base; }
  const base_iter_t &get() const { return base; }
  mmap_iterator &operator++() {
    if (base != end) {
      ++get();
      map();
    }
    return *this;
  }
  mmap_iterator operator++(int) {
    auto old = *this;
    ++*this;
    return old;
  }
  bool operator==(const mmap_iterator &r) const { return get() == r.get(); }
  bool operator!=(const mmap_iterator &r) const { return get() != r.get(); }

 private:
  void map() {
    if (base != end) {
      if constexpr (std::is_same_v<
                        type_traits::RemoveCvrT<
                            typename std::iterator_traits<T>::value_type>,
                        fs::path>) {
        cur = map_file((*base).string(), flags, populate);
      } else {
        cur = map_file(*base, flags, populate);
      }
    } else {
      cur = mapped_file_t();
    }
  }
  unsigned int flags;
  bool populate;
  mapped_file_t cur;
  T base;
  T end;
};

template <typename R>
using mmap_range = boost::iterator_range<mmap_iterator<
    utils::type_traits::RemoveCvrT<decltype(std::declval<R>().begin())>>>;

template <typename R>
mmap_range<R> make_mmap_range(R &v, unsigned int flags, bool populate) {
  using iterator =
      utils::type_traits::RemoveCvrT<decltype(std::declval<R>().begin())>;
  return mmap_range<R>(
      mmap_iterator<iterator>(v.begin(), v.end(), flags, populate),
      mmap_iterator<iterator>(v.end(), v.end(), flags, populate));
}

template <typename R>
auto make_mmap_range(const R &v, unsigned int flags, bool populate) {
  using iterator =
      utils::type_traits::RemoveCvrT<decltype(std::declval<R>().begin())>;
  return boost::make_iterator_range(
      mmap_iterator<iterator>(v.begin(), v.end(), flags, populate),
      mmap_iterator<iterator>(v.end(), v.end(), flags, populate));
}

namespace adaptor {
struct mmap {
  mmap(unsigned int flags_, bool populate_)
      : flags(flags_), populate(populate_) {}
  unsigned int flags = 0u;
  bool populate = false;
};

template <typename T>
auto operator|(T &p, const mmap &params) {
  return make_mmap_range<T>(p, params.flags, params.populate);
}

template <typename T>
auto operator|(const T &p, const mmap &params) {
  return make_mmap_range<T>(p, params.flags, params.populate);
}

}  // namespace adaptor

}  // namespace fuzzuf::utils::range
#endif
