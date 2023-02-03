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
 * @file call_with_nth.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_CALL_WITH_NTH_HPP
#define FUZZUF_INCLUDE_UTILS_CALL_WITH_NTH_HPP
#include <cstddef>
#include <iostream>
#include <utility>

#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::utils::struct_path {

struct DerefT {};
constexpr auto deref = DerefT();

template <typename T>
struct IdentT {};
template <typename T>
constexpr auto ident = IdentT<T>();

template <typename T, T v>
struct IntT {};
template <typename T, T v>
constexpr auto int_ = IntT<T, v>();

template <typename T, typename U, U T::*m>
struct MemT {};
template <typename T, typename U, U T::*m>
constexpr auto mem = MemT<T, U, m>();

template <std::size_t i>
struct ElemT {};
template <std::size_t i>
constexpr auto elem = ElemT<i>();

template <std::size_t i>
struct ArgT {};
template <std::size_t i>
constexpr auto arg = ArgT<i>();

namespace detail {
template <typename P>
struct GetValue;
template <template <typename...> typename L>
struct GetValue<L<>> {
  template <typename T>
  decltype(auto) operator()(T &&v) const {
    return std::forward<T>(v);
  }
};
template <template <typename...> typename L, typename T, typename... Tail>
struct GetValue<L<IdentT<T>, Tail...>> {
  template <typename... U>
  decltype(auto) operator()(U &&...) const {
    value = T();
    return value;
  }

 private:
  mutable T value;
};
template <template <typename...> typename L, typename T, T v, typename... Tail>
struct GetValue<L<IntT<T, v>, Tail...>> {
  template <typename... U>
  decltype(auto) operator()(U &&...) const {
    value = v;
    return value;
  }

 private:
  mutable T value;
};
template <template <typename...> typename L, typename... Tail>
struct GetValue<L<DerefT, Tail...>> {
  template <typename T>
  decltype(auto) operator()(T &&v) const {
    return GetValue<L<Tail...>>()(*v);
  }
};
template <template <typename...> typename L, typename... Tail, typename T,
          typename U, U T::*m>
struct GetValue<L<MemT<T, U, m>, Tail...>> {
  decltype(auto) operator()(T &&v) const {
    return GetValue<L<Tail...>>()(std::move(v.*m));
  }
  decltype(auto) operator()(T &v) const { return GetValue<L<Tail...>>()(v.*m); }
};
template <template <typename...> typename L, typename... Tail, std::size_t i>
struct GetValue<L<ElemT<i>, Tail...>> {
  template <typename T>
  decltype(auto) operator()(T &&v) const {
    return GetValue<L<Tail...>>()(v[i]);
  }
  template <typename T>
  decltype(auto) operator()(T &v) const {
    return GetValue<L<Tail...>>()(v[i]);
  }
};
template <std::size_t cur, std::size_t end, typename Enable = void>
struct GetNth;
template <std::size_t cur, std::size_t end>
struct GetNth<cur, end, std::enable_if_t<cur == end>> {
  template <typename Head, typename... Tail>
  decltype(auto) operator()(Head &&head, Tail &&...) const {
    return std::forward<Head>(head);
  }
};
template <std::size_t cur, std::size_t end>
struct GetNth<cur, end, std::enable_if_t<cur != end>> {
  template <typename Head, typename... Tail>
  decltype(auto) operator()(Head &&, Tail &&...tail) const {
    return GetNth<cur + 1u, end>()(std::forward<Tail>(tail)...);
  }
};
template <template <typename...> typename L, typename... Tail, std::size_t i>
struct GetValue<L<ArgT<i>, Tail...>> {
  template <typename... T>
  decltype(auto) operator()(T &&...v) const {
    return GetValue<L<Tail...>>()(GetNth<0u, i>()(std::forward<T>(v)...));
  }
};
}  // namespace detail

template <typename P, typename... T>
decltype(auto) GetValue(T &&...v) {
  return detail::GetValue<P>()(std::forward<T>(v)...);
}

namespace call_with_nth {
template <typename Path, typename F, typename... Args>
auto CallWithNthSingle(F &&func, Args &&...args) {
  func(GetValue<Path>(std::forward<Args>(args)...));
}

template <typename Path>
struct CallWithNthMultiple {
  template <typename F, typename... Args>
  void operator()(F &&func, Args &&...) const {
    func();
  }
};
template <template <typename...> typename L, typename Head, typename... Tail>
struct CallWithNthMultiple<L<Head, Tail...>> {
  template <typename F, typename... Args>
  void operator()(F &&func, Args &&...args) const {
    CallWithNthSingle<Head>(
        [&](auto &&v0) {
          CallWithNthMultiple<L<Tail...>>()(
              [&](auto &&...v1) {
                func(std::forward<decltype(v0)>(v0),
                     std::forward<decltype(v1)>(v1)...);
              },
              std::forward<Args>(args)...);
        },
        std::forward<Args>(args)...);
  }
};
}  // namespace call_with_nth

template <typename... T>
struct Path {
  template <typename F, typename... Args>
  void operator()(F &&func, Args &&...args) const {
    call_with_nth::CallWithNthSingle<Path>(std::forward<F>(func),
                                           std::forward<Args>(args)...);
  }
  constexpr auto operator*() const { return Path<T..., DerefT>(); }
};

template <typename... T>
struct Paths {
  template <typename F, typename... Args>
  auto operator()(F &&func, Args &&...args) const {
    call_with_nth::CallWithNthMultiple<Paths>()(std::forward<F>(func),
                                                std::forward<Args>(args)...);
  }
};

constexpr auto root = Path<>();

template <typename... CWD, typename Child>
constexpr auto operator/(const Path<CWD...> &, const Child &) {
  return Path<CWD..., Child>();
}

template <typename... CWD, typename T, typename U>
constexpr auto operator->*(const Path<CWD...> &, const U T::*m) {
  return Path<CWD..., MemT<T, U, m>>();
}

template <typename... L, typename... R>
constexpr auto operator&&(const Path<L...> &, const Path<R...> &) {
  return Paths<Path<L...>, Path<R...>>();
}
template <typename... L, typename... R>
constexpr auto operator&&(const Paths<L...> &, const Path<R...> &) {
  return Paths<L..., Path<R...>>();
}
template <typename... L, typename... R>
constexpr auto operator&&(const Path<L...> &, const Paths<R...> &) {
  return Paths<Path<L...>, R...>();
}
template <typename... L, typename... R>
constexpr auto operator&&(const Paths<L...> &, const Paths<R...> &) {
  return Paths<L..., R...>();
}

template <typename F, typename P>
struct PointedType {};
template <typename R, typename... Args, typename... Node>
struct PointedType<R(Args...), Path<Node...>> {
  using type = decltype(GetValue<Path<Node...>>(std::declval<Args>()...));
};
template <typename F, typename P>
using PointedTypeT = typename PointedType<F, type_traits::RemoveCvrT<P>>::type;

}  // namespace fuzzuf::utils::struct_path

#endif
