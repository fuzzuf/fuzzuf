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
#define BOOST_TEST_MODULE algorithms.libfuzzer.execute3
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/program_options.hpp>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/algorithms/libfuzzer/cli_compat/fuzzer.hpp"
#include "fuzzuf/algorithms/libfuzzer/executor/execute.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/executor/libfuzzer_executor_interface.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/sha1.hpp"
#include "fuzzuf/utils/which.hpp"

namespace po = boost::program_options;

/**
 * This test checks that libFuzzer+symcc finds more number of active inputs than
 * libFuzzer only.
 */
BOOST_AUTO_TEST_CASE(SymCC) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  const std::vector<std::vector<std::string> > args{
      {"fuzzuf", "libfuzzer",
       "-target=" FUZZUF_FUZZTOYS_DIR "/fuzz_toys-branch",
       "-symcc_target=" FUZZUF_FUZZTOYS_SYMCC_DIR "/fuzz_toys-branch",
       "-seed=1", "-runs=1000", "-exact_artifact_path=" + output_dir.string(),
       input_dir.string()},
      {"fuzzuf", "libfuzzer",
       "-target=" FUZZUF_FUZZTOYS_DIR "/fuzz_toys-branch",
       "-symcc_target=" FUZZUF_FUZZTOYS_SYMCC_DIR "/fuzz_toys-branch",
       "-symcc_freq=0", "-seed=1", "-runs=1000",
       "-exact_artifact_path=" + output_dir.string(), input_dir.string()},
      {"fuzzuf", "libfuzzer",
       "-target=" FUZZUF_FUZZTOYS_DIR "/fuzz_toys-branch",
       "-symcc_target=" FUZZUF_FUZZTOYS_SYMCC_DIR "/fuzz_toys-branch",
       "-symcc_freq=1", "-seed=1", "-runs=1000",
       "-exact_artifact_path=" + output_dir.string(), input_dir.string()},
      {"fuzzuf", "libfuzzer",
       "-target=" FUZZUF_FUZZTOYS_DIR "/fuzz_toys-branch",
       "-symcc_target=" FUZZUF_FUZZTOYS_SYMCC_DIR "/fuzz_toys-branch",
       "-symcc_freq=20", "-seed=1", "-runs=1000",
       "-exact_artifact_path=" + output_dir.string(), input_dir.string()},
      {"fuzzuf", "libfuzzer",
       "-target=" FUZZUF_FUZZTOYS_DIR "/fuzz_toys-branch", "-seed=1",
       "-runs=1000", "-exact_artifact_path=" + output_dir.string(),
       input_dir.string()}};
  std::vector<std::size_t> corpus_size;
  corpus_size.reserve(args.size());
  for (const auto &a : args) {
    BOOST_TEST_CHECKPOINT("begin");
    BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
    BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

    namespace lf = fuzzuf::algorithm::libfuzzer;
    using fuzzuf::executor::LibFuzzerExecutorInterface;
    {
      std::vector<std::uint8_t> initial_input{'+'};
      auto initial_input_name = fuzzuf::utils::ToSerializedSha1(initial_input);
      std::fstream fd((input_dir / initial_input_name).c_str(), std::ios::out);
      std::copy(initial_input.begin(), initial_input.end(),
                std::ostreambuf_iterator<char>(fd));
    }

    // Parse a sub-command
    po::positional_options_description subcommand;
    subcommand.add("fuzzer", 1);

    // Define global options
    po::options_description global_desc("Global options");
    global_desc.add_options()(
        "fuzzer", po::value<std::string>(),
        "Specify fuzzer to be used in your fuzzing campaign.");

    // Simulate command line args
    std::vector<const char *> cargs;
    cargs.reserve(a.size());
    std::transform(a.begin(), a.end(), std::back_inserter(cargs),
                   [](const auto &v) { return v.c_str(); });

    fuzzuf::cli::FuzzerArgs fargs{
        .argc = int(cargs.size()),
        .argv = cargs.data(),
        .global_options_description = global_desc,
    };

    lf::LibFuzzer fuzzer(fargs, fuzzuf::cli::GlobalFuzzerOptions(),
                         [](std::string &&m) { std::cout << m << std::flush; });

    while (!fuzzer.ShouldEnd()) {
      fuzzer.OneLoop();
    }
    corpus_size.push_back(
        std::count_if(fuzzer.GetVariables().corpus.corpus.begin(),
                      fuzzer.GetVariables().corpus.corpus.end(),
                      [](const auto &v) { return v.enabled; }));

    fs::remove_all(input_dir);
    fs::remove_all(output_dir);

    BOOST_TEST_CHECKPOINT("end");
  }
  // Number of active inputs in libFuzzer only is less than number of active
  // inputs in libFuzzer+SymCC
  BOOST_CHECK_LT(corpus_size[4], corpus_size[0]);
  BOOST_CHECK_EQUAL(corpus_size[4], corpus_size[1]);
  BOOST_CHECK_EQUAL(corpus_size[0], corpus_size[2]);
  BOOST_CHECK_EQUAL(corpus_size[0], corpus_size[3]);
}
