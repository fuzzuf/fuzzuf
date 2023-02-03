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
#define BOOST_TEST_MODULE exec_input.set
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/exec_input/exec_input_set.hpp"

#include <boost/test/unit_test.hpp>
#include <memory>
#include <set>

#include "fuzzuf/exec_input/exec_input.hpp"

BOOST_AUTO_TEST_CASE(ExecInputSetTest) {
  fuzzuf::exec_input::ExecInputSet input_set;

  int N = 5;
  for (int i = 0; i < N; i++) {
    input_set.CreateOnMemory((const u8*)"test", 4);
  }
  BOOST_CHECK_EQUAL(input_set.size(), N);

  auto v = input_set.get_ids();
  BOOST_CHECK_EQUAL(v.size(), N);
  std::set<u64> v_set(v.begin(), v.end());
  BOOST_CHECK_EQUAL(v_set.size(), N);

  u64 last_id = 0;
  for (int i = 0; i < N; i++) {
    input_set.erase(v[i]);
    last_id = v[i];
  }
  BOOST_CHECK_EQUAL(input_set.size(), 0);

  auto id = input_set.CreateOnMemory((const u8*)"test", 4)->GetID();
  BOOST_CHECK(input_set.get_ref(id) != std::nullopt);
  BOOST_CHECK(input_set.get_ref(last_id) == std::nullopt);
}
