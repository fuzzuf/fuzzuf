#include "fuzzuf/cli/fuzzer/afl_symcc/build_from_args.hpp"
#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/afl_symcc/fuzzer.hpp"
#include "fuzzuf/cli/fuzzer/afl/build_afl_fuzzer_from_args.hpp"
#include <boost/program_options.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace fuzzuf::cli::fuzzer::afl_symcc {
// Used only for CLI
std::unique_ptr<Fuzzer>
BuildFromArgs(const FuzzerArgs &fuzzer_args,
              const GlobalFuzzerOptions &global_options) {
  namespace po = boost::program_options;
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  AFLFuzzerOptions afl_options;
  SymCCOptions symcc_options;
  po::options_description fuzzer_desc("AFL options");
  std::vector<std::string> pargs;
  afl_options.forksrv = true;
  fuzzer_desc.add(fuzzer_args.global_options_description)
      .add_options()("dict_file",
                     po::value<std::string>(&afl_options.dict_file),
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
    fuzzuf::cli::fuzzer::afl::usage(fuzzer_desc);
  }
  if (!vm.count("symcc_target")) {
    fuzzuf::cli::fuzzer::afl::usage(fuzzer_desc);
  }
  std::vector<std::string> symcc_args(pargs.begin(), pargs.end());
  if (symcc_args.empty())
    symcc_args.push_back(symcc_options.target_path);
  else
    symcc_args[0] = symcc_options.target_path;
  const auto symcc_dir =
      fs::absolute(fs::path(global_options.out_dir) / "symcc");
  return std::unique_ptr<fuzzuf::algorithm::afl_symcc::AFLSymCCFuzzer>(
      new fuzzuf::algorithm::afl_symcc::AFLSymCCFuzzer(
          fuzzuf::cli::fuzzer::afl::BuildFuzzer<
              fuzzuf::algorithm::afl_symcc::AFLFuzzerTemplate<
                  fuzzuf::algorithm::afl::AFLState>,
              fuzzuf::algorithm::afl_symcc::AFLFuzzerTemplate<
                  fuzzuf::algorithm::afl::AFLState>,
              fuzzuf::executor::AFLExecutorInterface>(fuzzer_args.argv[0],
                                                      fuzzer_desc, afl_options,
                                                      pargs, global_options),
          std::move(symcc_options),
          std::shared_ptr<fuzzuf::executor::AFLSymCCExecutorInterface>(
              new fuzzuf::executor::AFLSymCCExecutorInterface(
                  std::shared_ptr<NativeLinuxExecutor>(new NativeLinuxExecutor(
                      std::move(symcc_args),
                      global_options.exec_timelimit_ms.value_or(
                          fuzzuf::algorithm::afl::option::GetExecTimeout<
                              fuzzuf::algorithm::afl::option::AFLTag>()),
                      global_options.exec_memlimit.value_or(
                          fuzzuf::algorithm::afl::option::GetMemLimit<
                              fuzzuf::algorithm::afl::option::AFLTag>()),
                      false, fs::path(global_options.out_dir) / "cur_input", 0,
                      0, false, {"SYMCC_OUTPUT_DIR=" + symcc_dir.string()},
                      {symcc_dir}))))));
}

} // namespace fuzzuf::cli::fuzzer::afl_symcc
