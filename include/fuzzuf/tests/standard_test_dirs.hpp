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
 * @file standard_test_dirs.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_TESTS_STANDARD_TEST_DIRS_HPP
#define FUZZUF_INCLUDE_TESTS_STANDARD_TEST_DIRS_HPP

#include <boost/scope_exit.hpp>
#include <cstdlib>
#include <fstream>
#include <string>

#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/sha1.hpp"

#define FUZZUF_STANDARD_TEST_DIRS                              \
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");    \
  auto* const raw_dirname = mkdtemp(root_dir_template.data()); \
  BOOST_CHECK(raw_dirname != nullptr);                         \
  auto root_dir = fs::path(raw_dirname);                       \
  auto input_dir = root_dir / "input";                         \
  auto output_dir = root_dir / "output";                       \
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);    \
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);   \
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }    \
  BOOST_SCOPE_EXIT_END

#define FUZZUF_SETUP_SINGLE_INITIAL_INPUT(input)                            \
  auto initial_input_name = fuzzuf::utils::ToSerializedSha1(input);         \
  std::fstream fd((input_dir / initial_input_name).c_str(), std::ios::out); \
  std::copy(input.begin(), input.end(), std::ostreambuf_iterator<char>(fd));

#define FUZZUF_SETUP_EXTERNAL_QUEUE                                         \
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir / "fuzzer1"), true);    \
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir / "fuzzer1" / "queue"), \
                    true);                                                  \
  {                                                                         \
    std::fstream key_file(                                                  \
        (output_dir / "fuzzer1" / "queue" / "id:000001").string(),          \
        std::ios::out | std::ios::binary);                                  \
    constexpr std::uint64_t key = 0x1234567890abcdef;                       \
    key_file.write(reinterpret_cast<const char*>(&key), sizeof(key));       \
  }

#endif
