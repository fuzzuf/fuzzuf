/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file map_file.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_VFS_SHARED_HPP
#define FUZZUF_INCLUDE_UTILS_VFS_SHARED_HPP
#include <memory>
#include <utility>

namespace fuzzuf::utils::vfs::adaptor {

template <typename Base> class Shared : public Base {
public:
  template <typename... Args>
  Shared(std::shared_ptr<void> &&p_, Args &&...args)
      : Base(std::forward<Args>(args)...), p(p_) {}

private:
  std::shared_ptr<void> p;
};
namespace detail {
struct SharedParams {
  std::shared_ptr<void> p;
};
}; // namespace detail
struct SharedTag {
  template <typename T> detail::SharedParams operator()(T p) const {
    return detail::SharedParams{std::forward<T>(p)};
  }
};
constexpr SharedTag shared;
namespace detail {
template <typename Base>
Shared<utils::type_traits::RemoveCvrT<Base>>
operator|(Base &&b, detail::SharedParams &&p) {
  return Shared<Base>(std::move(p.p), std::forward<Base>(b));
}
template <typename Base>
Shared<Base> operator|(Base &&b, const detail::SharedParams &p) {
  return Shared<Base>(p.p, std::forward<Base>(b));
}
} // namespace detail

} // namespace fuzzuf::utils::vfs::adaptor

#endif
