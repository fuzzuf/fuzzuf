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
 * fuzzufをCLIから実行した場合に近い方法でlibFuzzerを組み立て、libFuzzerのデフォルトのサイクル数だけ回し、その過程でサニタイザにかかったりabortしたりしないことを確認する
 * コマンドライン引数はexecute2と同じ動作をするように指定してある
 * (従ってexecute2とexecute3の結果が一致しない場合libFuzzerをCLIから使えるようにするための実装にバグがある)
 * 最後にfuzzerの状態と見つかったクラッシュパスをダンプする
 */
BOOST_AUTO_TEST_CASE(HierarFlowExecute) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";

  // Create input/output dirctory

  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  namespace lf = fuzzuf::algorithm::libfuzzer;
  using fuzzuf::executor::LibFuzzerExecutorInterface;

  BOOST_TEST_CHECKPOINT("before init state");

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
  std::vector<std::string> args{"fuzzuf",
                                "libfuzzer",
                                "-target=" FUZZUF_FUZZTOYS_DIR
                                "/fuzz_toys-brainf_ck",
                                "-seed=1",
                                "-verbosity=2",
                                "-runs=1000",
                                "-timeout=1",
                                "-dict=" TEST_DICTIONARY_DIR "/brainf_ck.dict",
                                "-exact_artifact_path=" + output_dir.string(),
                                "-print_pcs=1",
                                "-print_final_stats=1",
                                "-entropic=1",
                                "-reduce_depth=1",
                                "-reduce_input=1",
                                "-shrink=1",
                                "-shuffle=0",
                                "-len_control=10",
                                input_dir.string()};

  std::vector<const char *> cargs;
  cargs.reserve(args.size());
  std::transform(args.begin(), args.end(), std::back_inserter(cargs),
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

  BOOST_TEST_CHECKPOINT("after execution");
  {
    const auto &create_info = fuzzer.get_create_info();
    const auto output_file_path = create_info.output_dir / "result";
    const auto path_to_write_seed = create_info.output_dir / "cur_input";
    std::vector<LibFuzzerExecutorInterface> executor;
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-brainf_ck",
             output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size)));
    std::size_t solution_count = 0u;
    for (const auto &filename :
         fs::directory_iterator{create_info.output_dir}) {
      if (fs::is_regular_file(filename.status())) {
        auto mapped =
            fuzzuf::utils::map_file(filename.path().string(), O_RDONLY, true);
        std::vector<std::uint8_t> input(mapped.begin(), mapped.end());
        auto sha1 = fuzzuf::utils::ToSerializedSha1(input);
        if (sha1 != filename.path().filename().string()) continue;
        std::vector<std::uint8_t> output;
        std::vector<std::uint8_t> coverage;
        lf::InputInfo input_info;
        lf::executor::Execute(input, output, coverage, input_info, executor, 0u,
                              true);
        // target fails to execute found inputs
        BOOST_CHECK_NE(input_info.status,
                       fuzzuf::feedback::PUTExitReasonType::FAULT_NONE);
        ++solution_count;
      }
    }
    std::cout << "The fuzzer detected " << solution_count << " solutions."
              << std::endl;
    // at least one solution was found
    BOOST_CHECK_NE(solution_count, 0u);
  }
  BOOST_TEST_CHECKPOINT("done");
}
