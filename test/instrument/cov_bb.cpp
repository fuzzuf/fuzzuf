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
#define BOOST_TEST_MODULE instrument - cov - bb
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <random>

#include "config.h"
#include "create_file.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/python/python_fuzzer.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "move_to_program_location.hpp"

struct DiffInfo {
  std::vector<int> passed;
  std::vector<int> ignored;
};

/*
    throughout this PUT, we assume there is a mapping between seeds(or input)
   and integers (bit_seq) the mapping is just the same as little endian. for
   example, if bit_seq is 4, then the corresponding input would be "00100000" in
   the follwing comments, sometimes we refer seeds like "the seed corresponding
   to 4"
 */
std::unordered_map<int, u8> GetCoverage(
    fuzzuf::bindings::python::PythonFuzzer &fuzzer, int bit_seq) {
  // create seed corresponding to bit_seq
  std::vector<u8> buf;
  for (int i = 0; i < 8; i++) {
    int d = bit_seq >> i & 1;
    buf.emplace_back('0' + d);
  }

  auto id = fuzzer.AddSeed(8, buf);
  BOOST_CHECK(id != fuzzuf::exec_input::ExecInput::INVALID_INPUT_ID);
  auto pyseed_optional = fuzzer.GetPySeed(id);
  BOOST_CHECK(pyseed_optional.has_value());
  auto trace_optional = pyseed_optional->GetFeedback().GetBBTrace();
  BOOST_CHECK(trace_optional.has_value());
  return trace_optional.value();
}

// to test both fork server mode and non fork server mode, we specify forksrv
// via an argument moreover, "whether BB coverage can be retrieved" should be
// independent from need_afl_cov. so we test both cases, need_afl_cov=false,
// need_afl_cov=true
static void InstrumentCovBB(bool forksrv, bool need_afl_cov) {
  // cd $(dirname $0)
  MoveToProgramLocation();

  // Create root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  const auto raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
#ifdef HAS_CXX_STD_FILESYSTEM
  namespace fs = std::filesystem;
#else
  namespace fs = boost::filesystem;
#endif
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) {
    // Executed on this test exit
    fs::remove_all(root_dir);
  }
  BOOST_SCOPE_EXIT_END

  // Create input file
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  auto input_path = input_dir / "nothing";
  create_file(input_path.string(),
              "this seed is just nothing. we add more seeds later");

  // Create fuzzer instance
  auto fuzzer = fuzzuf::bindings::python::PythonFuzzer(
      {"../put_binaries/zeroone"}, input_dir.native(), output_dir.native(),
      1000, 10000, forksrv, need_afl_cov, true  // need_afl_cov, need_bb_cov
  );

  // Configurate fuzzer
  fuzzer.SuppressLog();

  // create "diffs" between 00000000 and 10000000, between 0000000 and 01000000,
  // ...
  auto base_cov = GetCoverage(fuzzer, 0);
  // coverages cannot be empty
  BOOST_CHECK(base_cov.size() > 0);

  DiffInfo diffs[8];
  for (int i = 0; i < 8; i++) {
    auto cov = GetCoverage(fuzzer, 1 << i);
    // coverages cannot be empty
    BOOST_CHECK(cov.size() > 0);

    // into DiffInfo::passed, append basic blocks which the seed corresponding
    // to (1 << i) passes, but which the seed corresponding to 0 doesn't pass
    for (const auto &itr : cov) {
      if (!base_cov.count(itr.first)) diffs[i].passed.emplace_back(itr.first);
    }
    // into DiffInfo::ignored, append basic blocks which the seed corresponding
    // to (1 << i) doesn't pass, but which the seed corresponding to 0 passes
    for (const auto &itr : base_cov) {
      if (!cov.count(itr.first)) diffs[i].ignored.emplace_back(itr.first);
    }

    std::string name(8, '0');
    name[i] = '1';
    std::cout << "---" << name << "---\n";
    std::cout << "IDs of nodes (BBs) which this input should pass:";
    for (int node_idx : diffs[i].passed) {
      std::cout << " " << node_idx;
    }
    std::cout << "\nIDs of nodes (BBs) which given input should not pass:";
    for (int node_idx : diffs[i].ignored) {
      std::cout << " " << node_idx;
    }
    std::cout << std::endl;

    // there must be some differences
    BOOST_CHECK(diffs[i].passed.size() > 0);
    BOOST_CHECK(diffs[i].ignored.size() > 0);

    // moreover, normally the difference should be just one node(where "var = 1"
    // or "var = 0" takes place)
    BOOST_CHECK_EQUAL(diffs[i].passed.size(), 1);
    BOOST_CHECK_EQUAL(diffs[i].ignored.size(), 1);
  }

  int lim = 1 << 8;
  for (int bit_seq = 0; bit_seq < lim; bit_seq++) {
    auto cov = GetCoverage(fuzzer, bit_seq);
    for (int i = 0; i < 8; i++) {
      // check if the i-th bit counting from LSB is set
      bool is_ith_set = bit_seq >> i & 1;
      if (is_ith_set) {
        // the i-th bit of this seed is set
        // that means seed bit_seq should have passed nodes in diffs[i].passed
        for (int node_idx : diffs[i].passed) {
          BOOST_CHECK(cov.count(node_idx) > 0);
        }
        // and that seed bit_seq should not have passed nodes in
        // diffs[i].ignored
        for (int node_idx : diffs[i].ignored) {
          BOOST_CHECK(cov.count(node_idx) == 0);
        }
      } else {
        // the i-th bit of this seed is not set
        // that means seed bit_seq should have passed nodes in diffs[i].ignored
        for (int node_idx : diffs[i].ignored) {
          BOOST_CHECK(cov.count(node_idx) > 0);
        }
        // and that seed bit_seq should not have passed nodes in diffs[i].passed
        for (int node_idx : diffs[i].passed) {
          BOOST_CHECK(cov.count(node_idx) == 0);
        }
      }
    }
  }
}

BOOST_AUTO_TEST_CASE(Test4CasesWithInstrumentCovBB) {
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      // 出力を入れないと、複数テストケースある場合、切れ目がどこかが分からず、どっちが失敗しているか分からない事に気づいた
      std::cout << "[*] InstrumentCovBB started with";
      if (i)
        std::cout << " ForkMode";
      else
        std::cout << " NonForkMode";
      if (j)
        std::cout << ", need_afl_cov=true" << std::endl;
      else
        std::cout << ", need_afl_cov=false" << std::endl;

      InstrumentCovBB(i != 0, j != 0);
      std::cout << "[*] InstrumentCovBB ended" << std::endl;
    }
  }
}
