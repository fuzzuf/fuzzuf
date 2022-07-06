#include "fuzzuf/cli/fuzzer/afl_symcc/build_from_args.hpp"

#include <boost/program_options.hpp>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/afl_symcc/fuzzer.hpp"
#include "fuzzuf/cli/fuzzer/afl/build_afl_fuzzer_from_args.hpp"

namespace fuzzuf::cli::fuzzer::afl_symcc {
// Used only for CLI
std::unique_ptr<fuzzuf::fuzzer::Fuzzer> BuildFromArgs(
    const FuzzerArgs &fuzzer_args, const GlobalFuzzerOptions &global_options) {
  namespace po = boost::program_options;
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  afl::AFLFuzzerOptions afl_options;
  SymCCOptions symcc_options;
  po::options_description fuzzer_desc("AFL options");
  std::vector<std::string> pargs;
  afl_options.forksrv = true;
  fuzzer_desc.add(fuzzer_args.global_options_description)
      .add_options()("dict_file,x",
                     po::value<std::vector<std::string>>(&afl_options.dict_file)
                         ->composing(),
                     "Load additional dictionary file.")(
          "pargs", po::value<std::vector<std::string>>(&pargs),
          "Specify PUT and args for PUT.")(
          "frida",
          po::value<bool>(&afl_options.frida_mode)
              ->default_value(afl_options.frida_mode),
          "Enable/disable frida mode. Default to false.")(
          "symcc_target", po::value<std::string>(&symcc_options.target_path),
          "Path to the target executable compiled by SymCC.")(
          "symcc_freq", po::value<std::size_t>(&symcc_options.symcc_freq),
          "SymCC execution frequency."
          "If 0, SymCC is never executed."
          "Otherwise, SymCC is executed if recent n local loop blocks didn't "
          "change the corpus."
          "Default 1.");

  po::variables_map vm;
  po::store(po::command_line_parser(fuzzer_args.argc, fuzzer_args.argv)
                .options(fuzzer_desc)
                .positional(pargs_desc)
                .run(),
            vm);
  po::notify(vm);

  if (global_options.help) {
    std::cout << "Help:" << std::endl;
    std::cout << fuzzer_desc << std::endl;
    std::exit(1);
  }
  if (!vm.count("symcc_target")) {
    std::cout << "Help:" << std::endl;
    std::cout << fuzzer_desc << std::endl;
    std::exit(1);
  }
  std::vector<std::string> symcc_args(pargs.begin(), pargs.end());
  if (symcc_args.empty())
    symcc_args.push_back(symcc_options.target_path);
  else
    symcc_args[0] = symcc_options.target_path;
  const auto symcc_dir =
      fs::absolute(fs::path(global_options.out_dir) / "symcc");
  namespace as = algorithm::afl_symcc;
  namespace afl = algorithm::afl;
  return std::unique_ptr<as::AFLSymCCFuzzer>(new as::AFLSymCCFuzzer(
      cli::fuzzer::afl::BuildFuzzer<as::AFLFuzzerTemplate<afl::AFLState>,
                                    as::AFLFuzzerTemplate<afl::AFLState>,
                                    executor::AFLExecutorInterface>(
          fuzzer_args.argv[0], fuzzer_desc, afl_options, pargs, global_options),
      std::move(symcc_options),
      std::shared_ptr<executor::AFLSymCCExecutorInterface>(
          new executor::AFLSymCCExecutorInterface(
              std::shared_ptr<fuzzuf::executor::NativeLinuxExecutor>(
                  new fuzzuf::executor::NativeLinuxExecutor(
                      std::move(symcc_args),
                      global_options.exec_timelimit_ms.value_or(
                          afl::option::GetExecTimeout<afl::option::AFLTag>()),
                      global_options.exec_memlimit.value_or(
                          afl::option::GetMemLimit<afl::option::AFLTag>()),
                      false, fs::path(global_options.out_dir) / "cur_input", 0,
                      0, false, {"SYMCC_OUTPUT_DIR=" + symcc_dir.string()},
                      {symcc_dir}))))));
}

}  // namespace fuzzuf::cli::fuzzer::afl_symcc
