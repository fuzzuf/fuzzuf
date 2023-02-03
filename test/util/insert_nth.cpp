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
#define BOOST_TEST_MODULE util.InsertNth
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/utils/type_traits/insert_nth.hpp"

#include <boost/test/unit_test.hpp>
#include <type_traits>

template <unsigned int i>
struct num_t {};

BOOST_AUTO_TEST_CASE(InsertTemplateParameter) {
  BOOST_CHECK((std::is_same_v<
               fuzzuf::utils::type_traits::InsertNthT<
                   1U, num_t<3U>, std::tuple<num_t<0U>, num_t<1U>, num_t<2U>>>,
               std::tuple<num_t<0U>, num_t<3U>, num_t<1U>, num_t<2U>>>));
}

BOOST_AUTO_TEST_CASE(InsertFunctionParameter) {
  BOOST_CHECK(
      (std::is_same_v<fuzzuf::utils::type_traits::InsertNthT<
                          1U, num_t<3U>, int(num_t<0U>, num_t<1U>, num_t<2U>)>,
                      int(num_t<0U>, num_t<3U>, num_t<1U>, num_t<2U>)>));
}

BOOST_AUTO_TEST_CASE(InsertInteger) {
  BOOST_CHECK((std::is_same_v<fuzzuf::utils::type_traits::InsertNthT<
                                  1U, std::integer_sequence<int, 6>,
                                  std::integer_sequence<int, 3, 4, 5>>,
                              std::integer_sequence<int, 3, 6, 4, 5>>));
}
