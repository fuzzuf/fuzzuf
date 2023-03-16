/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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
 * @file options.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/eclipser/cli_compat/options.hpp"

#include <boost/program_options.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "fuzzuf/algorithms/eclipser/core/options.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/utils/load_inputs.hpp"
#include "fuzzuf/utils/range_traits.hpp"


namespace fuzzuf::algorithm::eclipser {

auto CreateOptions(options::FuzzOption &dest)
    -> boost::program_options::options_description {
  namespace po = boost::program_options;
  po::options_description desc("Options");
  desc.add_options()(
    "verbose,v",
    po::value<int>(&dest.verbosity),
    "Verbosity level to control debug messages (default:0)."
  )
  (
    "timelimit,t",
    po::value<int>(&dest.timelimit),
    "Timeout for fuzz testing (in seconds)."
  )
  (
    "outputdir,o",
    po::value<std::string>(&dest.out_dir),
    "Directory to store testcase outputs."
  )
  (
    "syncdir,s",
    po::value<std::string>(&dest.sync_dir),
    "Directory shared with AFL instances"
  )
  (
    "program,p",
    po::value<std::string>(&dest.target_prog),
    "Target program for test case generation with fuzzing."
  )
  (
    "exectimeout,e",
    po::value<std::uint64_t>(&dest.exec_timeout),
    "Execution timeout (ms) for a fuzz run (default:500)"
  )
  (
    "architecture",
    po::value<std::string>(),
    "Target program architecture (x86|x64) (default:x64)"
  )
  (
    "noforkserver",
    po::bool_switch(),
    "Do not use fork server for target program execution"
  )
  (
    "inputdir,i",
    po::value<std::string>(&dest.input_dir),
    "Directory containing initial seeds."
  )
  (
    "arg",
    po::value<std::string>(&dest.arg),
    "Command-line argument of the target program to fuzz."
  )
  (
    "filepath,f",
    po::value<std::string>(),
    "File input's (fixed) path"
  )
  (
    "nsolve",
    po::value<int>(&dest.n_solve),
    "Number of branches to flip in grey-box concolic testing "
    "when an execution path is given. 'N_solve' parameter in "
    "the paper."
  )
  (
    "nspawn",
    po::value<int>(&dest.n_spawn),
    "Number of byte values to initially spawn in grey-box "
    "concolic testing. 'N_spawn' parameter in the paper. "
  );
  return desc;
}

auto PostProcess(
  const boost::program_options::options_description &desc,
  int argc,
  const char *argv[],
  const cli::GlobalFuzzerOptions &global,
  std::function<void(std::string &&)> &&sink,
  options::FuzzOption &dest
) -> bool {
  namespace po = boost::program_options;
  po::variables_map vm;
  po::store(
    po::command_line_parser( argc, argv )
      .options( desc )
      .style(
        po::command_line_style::default_style |
        po::command_line_style::allow_long_disguise
      )
      .run(),
    vm
  );
  po::notify(vm);

  if (global.logger != utils::Logger::Stdout && global.log_file) {
    std::shared_ptr<std::fstream> fd(new std::fstream(
        global.log_file->string(), std::ios::out | std::ios::binary));
    dest.sink = [fd = std::move(fd)](std::string &&m) {
      *fd << m << std::flush;
    };
  } else {
    dest.sink = std::move( sink );
  }

  if (global.help == 1) {
    std::ostringstream out;
    out << "Usage : " << std::endl;
    out << "  $ fuzzuf [eclipser] -- [options]\n";
    out << desc << std::endl;
    dest.sink(std::string(out.str()));
    return false;
  }

  if( !fs::exists( dest.target_prog ) ) {
    std::ostringstream out;
    out << "Target program " << dest.target_prog << " does not exist." << std::endl;
    dest.sink(std::string(out.str()));
    return false;
  }

  fs::create_directories( dest.input_dir );
  fs::create_directories( dest.out_dir );
  fs::create_directories( dest.sync_dir );

  if( vm.count( "architecture" ) ) {
    if( vm[ "architecture" ].as< std::string >() == "x86" ) {
      dest.architecture = Arch::X86;
    }
    else if( vm[ "architecture" ].as< std::string >() == "x64" ) {
      dest.architecture = Arch::X64;
    }
    else {
      std::ostringstream out;
      out << "The architecture " << vm[ "architecture" ].as< std::string >() << " is not supported." << std::endl;
      dest.sink(std::string(out.str()));
      return false;
    }
  }
  dest.fork_server = !vm[ "noforkserver" ].as< bool >();
  if( vm.count( "filepath" ) ) {
    dest.fuzz_source = FileInput{ vm[ "filepath" ].as< std::string >() };
  }
  else {
    dest.fuzz_source = StdInput{};
  }
  dest.rng.seed(std::random_device()());
  return true;
}

}


