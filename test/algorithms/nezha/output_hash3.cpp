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
#define BOOST_TEST_MODULE algorithms.output_hash3
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <array>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/executor/execute.hpp"
#include "fuzzuf/algorithms/nezha/cli_compat/fuzzer.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/sha1.hpp"
#include "fuzzuf/utils/which.hpp"

/**
 * fuzzufをCLIから実行した場合に近い方法でNezhaを組み立て、libFuzzerのデフォルトのサイクル数だけ回し、その過程でサニタイザにかかったりabortしたりしないことを確認する
 * コマンドライン引数はoutput_hash2と同じ動作をするように指定してある
 * (従ってoutput_hash2とoutput_hash3の結果が一致しない場合NezhaをCLIから使えるようにするための実装にバグがある)
 * 最後にfuzzerの状態と見つかった実装毎に挙動が変わる入力値をダンプする
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
  namespace ne = fuzzuf::algorithm::nezha;
  using fuzzuf::executor::LibFuzzerExecutorInterface;

  BOOST_TEST_CHECKPOINT("before init state");

  {
    std::vector<std::uint8_t> initial_input{'1'};
    auto initial_input_name = fuzzuf::utils::ToSerializedSha1(initial_input);
    std::fstream fd((input_dir / initial_input_name).c_str(), std::ios::out);
    std::copy(initial_input.begin(), initial_input.end(),
              std::ostreambuf_iterator<char>(fd));
  }

  std::vector<std::string> args{
      "foo",
      "-target=" FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv_small",
      "-target=" FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv_small",
      "-target=" FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv",
      "-seed=1",
      "-verbosity=2",
      "-runs=250",
      "-timeout=1",
      "-dict=" TEST_DICTIONARY_DIR "/csv.dict",
      "-exact_artifact_path=" + output_dir.string(),
      "-print_pcs=1",
      "-print_final_stats=1",
      "-entropic=1",
      "-use_output=1",
      "-len_control=10",
      input_dir.string()};
  std::vector<const char *> cargs;
  cargs.reserve(args.size());
  std::transform(args.begin(), args.end(), std::back_inserter(cargs),
                 [](const auto &v) { return v.c_str(); });
  fuzzuf::cli::FuzzerArgs wrapped_args;
  wrapped_args.argc = int(cargs.size()) - 1;
  wrapped_args.argv = std::next(cargs.data());

  ne::NezhaFuzzer fuzzer(wrapped_args, fuzzuf::cli::GlobalFuzzerOptions(),
                         [](std::string &&m) { std::cout << m << std::flush; });

  while (!fuzzer.ShouldEnd()) {
    fuzzer.OneLoop();
  }

  BOOST_TEST_CHECKPOINT("after execution");
  {
    const auto &create_info = fuzzer.get_create_info();
    namespace tt = boost::test_tools;
    const auto output_file_path = create_info.output_dir / "result";
    const auto path_to_write_seed = create_info.output_dir / "cur_input";
    std::vector<LibFuzzerExecutorInterface> executor;
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv_small",
             output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size, true)));
    executor.push_back(std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
        new fuzzuf::executor::NativeLinuxExecutor(
            {FUZZUF_FUZZTOYS_DIR "/fuzz_toys-csv", output_file_path.string()},
            create_info.exec_timelimit_ms, create_info.exec_memlimit,
            create_info.forksrv, path_to_write_seed, create_info.afl_shm_size,
            create_info.bb_shm_size, true)));
    std::size_t solution_count = 0u;
    ne::known_outputs_t known;
    for (const auto &filename :
         fs::directory_iterator{create_info.output_dir}) {
      if (fs::is_regular_file(filename.status())) {
        auto mapped =
            fuzzuf::utils::map_file(filename.path().string(), O_RDONLY, true);
        std::vector<std::uint8_t> input(mapped.begin(), mapped.end());
        const auto leaf = filename.path().filename().string();
        static const auto expected_prefix = std::string("diff_");
        if (leaf.size() >= expected_prefix.size() &&
            std::equal(leaf.begin(),
                       std::next(leaf.begin(), expected_prefix.size()),
                       expected_prefix.begin(), expected_prefix.end())) {
          ne::outputs_t hash;
          {
            lf::InputInfo input_info;
            std::vector<std::uint8_t> output;
            std::vector<std::uint8_t> coverage;
            lf::executor::Execute(input, output, coverage, input_info, executor,
                                  0u, true);
            hash.push_back(ne::output_hash()(output));
          }
          {
            lf::InputInfo input_info;
            std::vector<std::uint8_t> output;
            std::vector<std::uint8_t> coverage;
            lf::executor::Execute(input, output, coverage, input_info, executor,
                                  1u, true);
            hash.push_back(ne::output_hash()(output));
          }
          // each targets output different message to stdout
          bool is_unique = known.insert(std::move(hash)).second;
          BOOST_CHECK(is_unique);
          ++solution_count;
        }
      }
    }
    std::cout << "The fuzzer detected " << solution_count << " solutions."
              << std::endl;
    // at least one solution was found
    BOOST_CHECK_NE(solution_count, 0u);
  }

  BOOST_TEST_CHECKPOINT("done");
}
