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
#define BOOST_TEST_MODULE util.status
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/utils/status.hpp"

#include <boost/test/unit_test.hpp>

enum class different_Order { DISCONNECTED, CONFLICT, BAD_REQUEST, OK, UNKNOWN };

enum class partial_t { UNKNOWN, OK };

// status_tからstatus_tへのstrictなキャストが出来る事を確認する
BOOST_AUTO_TEST_CASE(Strict) {
  BOOST_CHECK_EQUAL(fuzzuf::utils::statusCast<fuzzuf::utils::status_t>(
                        fuzzuf::utils::status_t::OK),
                    fuzzuf::utils::status_t::OK);
}

// status_tから並び順の異なるdifferent_Orderにキャストしても名前通りの変換が行われる事を確認する
// different_Orderからstatus_tへの変換も同様に行える事を確認する
BOOST_AUTO_TEST_CASE(DifferentOrder) {
  BOOST_CHECK(((fuzzuf::utils::statusCast<different_Order, false>(
                   fuzzuf::utils::status_t::OK)) == different_Order::OK));
  BOOST_CHECK_EQUAL((fuzzuf::utils::statusCast<fuzzuf::utils::status_t>(
                        different_Order::BAD_REQUEST)),
                    fuzzuf::utils::status_t::BAD_REQUEST);
}

// status_tから要素の足りないpartial_tにキャストしても非strictモードなら正しく変換できる事を確認する
// partial_tからstatus_tへの変換はstrictモードで行える事を確認する
BOOST_AUTO_TEST_CASE(Partial) {
  BOOST_CHECK(((fuzzuf::utils::statusCast<partial_t, false>(
                   fuzzuf::utils::status_t::OK)) == partial_t::OK));
  BOOST_CHECK(
      ((fuzzuf::utils::statusCast<partial_t, false>(
           fuzzuf::utils::status_t::BAD_REQUEST)) == partial_t::UNKNOWN));
  BOOST_CHECK_EQUAL(
      (fuzzuf::utils::statusCast<fuzzuf::utils::status_t>(partial_t::OK)),
      fuzzuf::utils::status_t::OK);
}

// status_tから文字列に変換できる事を確認する
BOOST_AUTO_TEST_CASE(ToString) {
  BOOST_CHECK_EQUAL(
      fuzzuf::utils::statusCast<std::string>(fuzzuf::utils::status_t::OK),
      std::string("OK"));
}

// 文字列からstatus_tに変換できる事を確認する
// 文字列の場合strictモードでも存在しない値がUNKNOWNになる事を確認する
BOOST_AUTO_TEST_CASE(FromString) {
  BOOST_CHECK_EQUAL(fuzzuf::utils::statusCast<fuzzuf::utils::status_t>("OK"),
                    fuzzuf::utils::status_t::OK);
  BOOST_CHECK_EQUAL(fuzzuf::utils::statusCast<fuzzuf::utils::status_t>("HOGE"),
                    fuzzuf::utils::status_t::UNKNOWN);
}
