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
#define BOOST_TEST_MODULE util.exec_command
#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>
#include <string>
#include <vector>

#include "fuzzuf/utils/common.hpp"

BOOST_AUTO_TEST_CASE(ExecuteCommand) {
  std::vector<std::string> cmd;

  cmd = {};
  BOOST_CHECK_EQUAL(fuzzuf::utils::ExecuteCommand(cmd), -1);

  cmd = {"true"};
  BOOST_CHECK_EQUAL(fuzzuf::utils::ExecuteCommand(cmd), 0);

  cmd = {"false"};
  BOOST_CHECK_EQUAL(fuzzuf::utils::ExecuteCommand(cmd), 1);

  cmd = {"sh", "-c", "sleep 0.1; true"};
  BOOST_CHECK_EQUAL(fuzzuf::utils::ExecuteCommand(cmd), 0);

  cmd = {"sh", "-c", "sleep 0.1; false"};
  BOOST_CHECK_EQUAL(fuzzuf::utils::ExecuteCommand(cmd), 1);

  cmd = {"sh", "-c", "exit 123"};
  BOOST_CHECK_EQUAL(fuzzuf::utils::ExecuteCommand(cmd), 123);

  cmd = {"sh", "-c", "exit 777"};  // WEXITSTATUS(0x309) == 9
  BOOST_CHECK_EQUAL(fuzzuf::utils::ExecuteCommand(cmd), 9);

  cmd = {"non-existing_command", "--hello", "world"};
  BOOST_CHECK_EQUAL(fuzzuf::utils::ExecuteCommand(cmd), 1);
}
