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
#define BOOST_TEST_MODULE util.call_with_nth
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/utils/call_with_nth.hpp"

#include <array>
#include <boost/test/unit_test.hpp>
#include <string>

#include "fuzzuf/utils/which.hpp"

struct fuga {
  int x = 8;
  int y = 9;
};
struct hoge {
  std::array<fuga, 3u> a;
};

BOOST_AUTO_TEST_CASE(SingleArg) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  int a = 1u;
  float b = 2.f;
  std::string c("hoge");
  int d = 4u;
  (sp::root / sp::arg<0>)([&](auto &&v) { v = 0u; }, a, b, c, d);
  BOOST_CHECK_EQUAL(a, 0);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(MultipleArgs) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  int a = 1u;
  float b = 2.f;
  std::string c("hoge");
  int d = 4u;
  (
    sp::root/sp::arg< 0 > &&
    sp::root/sp::arg< 2 >
  )(
    [&]( auto &&v, auto &&w ) {
      v = 0u;
      w = "fuga";
    },
    a, b, c, d
  );

  BOOST_CHECK_EQUAL(a, 0);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "fuga");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(SingleDeref) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  std::unique_ptr<int> a(new int(1u));
  float b = 2.f;
  std::string c("hoge");
  int d = 4u;
  (sp::root / sp::arg<0> / sp::deref)([&](auto &&v) { v = 0u; }, a, b, c, d);
  BOOST_CHECK_EQUAL(*a, 0);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(MultipleDeref) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  std::unique_ptr<int> a(new int(1u));
  std::unique_ptr<float> b(new float(2.f));
  std::string c("hoge");
  int d = 4u;
  (*(sp::root / sp::arg<0>)&&sp::root / sp::arg<1> / sp::deref)(
      [&](auto &&v, auto &&w) {
        v = 0u;
        w = 5.f;
      },
      a, b, c, d);

  BOOST_CHECK_EQUAL(*a, 0);
  BOOST_CHECK_EQUAL(*b, 5.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(SingleElem) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  int a = 1u;
  float b = 2.f;
  std::string c("hoge");
  int d = 4u;
  (sp::root / sp::arg<2> / sp::elem<1>)([&](auto &&v) { v = 'x'; }, a, b, c, d);
  BOOST_CHECK_EQUAL(a, 1);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hxge");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(MultipleElem) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  int a = 1u;
  std::vector<int> b{6, 7, 8};
  std::string c("hoge");
  int d = 4u;
  (
    sp::root/sp::arg< 1 >/sp::elem<0> &&
    sp::root/sp::arg< 2 >/sp::elem<1>
  )(
    [&]( auto &&v, auto &&w ) {
      v = 0u;
      w = 'x';
    },
    a, b, c, d
  );

  BOOST_CHECK_EQUAL(a, 1);
  BOOST_CHECK_EQUAL(b[0], 0);
  BOOST_CHECK_EQUAL(b[1], 7);
  BOOST_CHECK_EQUAL(b[2], 8);
  BOOST_CHECK_EQUAL(c, "hxge");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(SingleMem) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  fuga a;
  float b = 2.f;
  std::string c("hoge");
  int d = 4u;
  (sp::root / sp::arg<0> /
   sp::mem<fuga, int, &fuga::y>)([&](auto &&v) { v = 2; }, a, b, c, d);
  BOOST_CHECK_EQUAL(a.x, 8);
  BOOST_CHECK_EQUAL(a.y, 2);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(MultipleMem) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  fuga a;
  float b = 2.f;
  std::string c("hoge");
  fuga d;
  (
    sp::root/sp::arg< 0 >/sp::mem<fuga,int,&fuga::y> &&
    sp::root/sp::arg< 3 >/sp::mem<fuga,int,&fuga::x>
  )(
    [&]( auto &&v, auto &&w ) {
      v = 2;
      w = 3;
    },
    a, b, c, d
  );

  BOOST_CHECK_EQUAL(a.x, 8);
  BOOST_CHECK_EQUAL(a.y, 2);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d.x, 3);
  BOOST_CHECK_EQUAL(d.y, 9);
}

BOOST_AUTO_TEST_CASE(SingleIdent) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  int a = 1u;
  float b = 2.f;
  std::string c("hoge");
  int d = 4u;
  (sp::root / sp::ident<int>)([&](auto &&v) { v = 0u; }, a, b, c, d);
  BOOST_CHECK_EQUAL(a, 1);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(MultipleIdent) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  int a = 1u;
  float b = 2.f;
  std::string c("hoge");
  int d = 4u;
  (
    sp::root/sp::ident< int > &&
    sp::root/sp::ident< int >
  )(
    [&]( auto &&v, auto &&w ) {
      v = 0u;
      w = 1u;
    },
    a, b, c, d
  );

  BOOST_CHECK_EQUAL(a, 1);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d, 4);
}

BOOST_AUTO_TEST_CASE(SingleInt) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  int a = 1u;
  float b = 2.f;
  std::string c("hoge");
  int d = 4;
  int e = 0;
  (sp::root / sp::int_< int, 6 >)([&](auto &&v) { e = v; v = 1; }, a, b, c, d);
  BOOST_CHECK_EQUAL(a, 1);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d, 4);
  BOOST_CHECK_EQUAL(e, 6);
}

BOOST_AUTO_TEST_CASE(MultipleInt) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  int a = 1u;
  float b = 2.f;
  std::string c("hoge");
  int d = 4u;
  int e = 0u;
  int f = 0u;
  (
    sp::root/sp::int_< int, 7 > &&
    sp::root/sp::int_< int, 8 >
  )(
    [&]( auto &&v, auto &&w ) {
      e = v;
      f = w;
      v = 9;
      w = 10;
    },
    a, b, c, d
  );

  BOOST_CHECK_EQUAL(a, 1);
  BOOST_CHECK_EQUAL(b, 2.f);
  BOOST_CHECK_EQUAL(c, "hoge");
  BOOST_CHECK_EQUAL(d, 4);
  BOOST_CHECK_EQUAL(e, 7);
  BOOST_CHECK_EQUAL(f, 8);
}

BOOST_AUTO_TEST_CASE(PointedType) {
  namespace utils = fuzzuf::utils;
  namespace sp = fuzzuf::utils::struct_path;
  BOOST_CHECK((std::is_same_v<
               sp::PointedTypeT<
                   void(hoge &, fuga &),
                   decltype(sp::root / sp::arg<0> /
                            sp::mem<hoge, std::array<fuga, 3u>, &hoge::a> /
                            sp::elem<0> / sp::mem<fuga, int, &fuga::y>)>,
               int &>));
}
