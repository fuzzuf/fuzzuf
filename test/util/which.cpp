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
#define BOOST_TEST_MODULE util.which
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/utils/which.hpp"

#include <boost/test/unit_test.hpp>

#include "fuzzuf/utils/filesystem.hpp"

// whichが見つけてきたteeのパスにコマンドが存在することを確認する
BOOST_AUTO_TEST_CASE(Which) {
  BOOST_CHECK(fs::exists(fuzzuf::utils::which(fs::path("tee"))));
}
