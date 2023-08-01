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
 * @file fuzzer.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/eclipser/cli_compat/options.hpp"
#include "fuzzuf/algorithms/eclipser/cli_compat/fuzzer.hpp"
#include "fuzzuf/algorithms/eclipser/core/executor.hpp"
#include "fuzzuf/algorithms/eclipser/core/utils.hpp"
#include "fuzzuf/algorithms/eclipser/fuzz/fuzz.hpp"
#include "fuzzuf/algorithms/eclipser/fuzz/test_case.hpp"
#include "fuzzuf/algorithms/eclipser/fuzz/scheduler.hpp"


namespace fuzzuf::algorithm::eclipser {
EclipserFuzzer::EclipserFuzzer(
  cli::FuzzerArgs &fuzzer_args,
  const cli::GlobalFuzzerOptions &global,
  std::function<void(std::string &&)> &&sink_
) {
  opts.out_dir = global.out_dir;
  auto desc = CreateOptions( opts );

  if (!PostProcess(fuzzer_args.global_options_description.add(desc),
                   fuzzer_args.argc, fuzzer_args.argv, global, std::move(sink_),
                   opts)) {
    end_ = true;
    return;
  }
  executor::Initialize( opts );
  test_case::Initialize( opts.out_dir );
  scheduler::Initialize();

}
void EclipserFuzzer::OneLoop() {
  if( end_ ) return;
  FuzzUntilEmpty(
    []( std::string &&m ) {
      Log(
        []( std::string &&m ) {
          std::cout << m << std::flush;
       },
       std::move( m )
      );
    },
    opts.rng,
    opts
  );
  exit( 0 );
}

}

