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
#define BOOST_TEST_MODULE algorithms.rezzuf_kscheduler.select_seed
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/test/unit_test.hpp>

#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/select_seed.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/load_seed_if_needed.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/abandon_entry.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/fuzzer.hpp"
#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/utils/count_regular_files.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/kscheduler/gen_dyn_weight.hpp"
#include "fuzzuf/utils/copy.hpp"

BOOST_AUTO_TEST_CASE(SelectSeed) {
  // Setup root directory
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_STANDARD_TEST_DIRS
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  BOOST_TEST_CHECKPOINT("before init state");

  fs::current_path( root_dir );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"harfbuzz"/"katz_cent", root_dir/"katz_cent" );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"harfbuzz"/"border_edges", root_dir/"border_edges" );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"harfbuzz"/"child_node", root_dir/"child_node" );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"harfbuzz"/"parent_node", root_dir/"parent_node" );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"harfbuzz"/"graph_data_pack", root_dir/"graph_data_pack" );
  fuzzuf::utils::kscheduler::GenDynWeight gen_dyn_weight(
    FUZZUF_KSCHEDULER_SCRIPT_DIR "/gen_dyn_weight.py",
    FUZZUF_NK_DIR
  );

  for( const auto &e: fs::directory_iterator( fs::path( TEST_SOURCE_DIR )/"put"/"kscheduler"/"harfbuzz"/"harfbuzz"/"test"/"shaping"/"fonts"/"sha1sum" ) ) {
    fuzzuf::utils::copy( e.path(), input_dir );
  }

  BOOST_TEST_CHECKPOINT("initialized dirs");

  const char *argv[] = {"fuzzuf",
                        "rezzuf_kscheduler",
                        "-i",
                        input_dir.c_str(),
                        "-o",
                        output_dir.c_str(),
			"-e",
			"forkserver",
			"--forksrv",
			"true",
			"-s",
                        TEST_BINARY_DIR "/put/kscheduler/harfbuzz/kscheduler-harfbuzz",
			"@@",
                        nullptr};
  constexpr int argc = 13;
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);
  const auto &state = dynamic_cast< fuzzuf::algorithm::rezzuf_kscheduler::Fuzzer* >( fuzzer.get() )->GetState();
  auto fuzz_loop = fuzzuf::hierarflow::CreateDummyParent<void(void)>();
  auto select_seed = fuzzuf::hierarflow::CreateNode<fuzzuf::algorithm::rezzuf_kscheduler::SelectSeed>(*state);
  auto cull_queue = fuzzuf::hierarflow::CreateNode<fuzzuf::algorithm::afl::routine::other::CullQueueTemplate<fuzzuf::algorithm::rezzuf_kscheduler::State>>(*state);
  auto load_seed_if_needed = fuzzuf::hierarflow::CreateNode<fuzzuf::algorithm::rezzuf_kscheduler::LoadSeedIfNeeded>(*state);
  auto abandon_node =  fuzzuf::hierarflow::CreateNode<fuzzuf::algorithm::rezzuf_kscheduler::AbandonEntry>(*state);
  auto retry_calibrate =
      fuzzuf::hierarflow::CreateNode<fuzzuf::algorithm::afl::routine::other::RetryCalibrateTemplate<fuzzuf::algorithm::rezzuf_kscheduler::State>>(*state, *abandon_node);

  std::shared_ptr<typename fuzzuf::algorithm::rezzuf_kscheduler::State::OwnTestcase > testcase;
  auto probe = fuzzuf::hierarflow::CreateNode<fuzzuf::algorithm::afl::routine::other::Probe<fuzzuf::algorithm::rezzuf_kscheduler::State>>(
    [&]( const auto &t ) -> bool {
      testcase = t;
      return true;
    }
  );
  fuzz_loop << (select_seed || cull_queue);
  cull_queue << ( load_seed_if_needed || retry_calibrate || probe );
  fuzzer->OneLoop();
  fuzz_loop();

  unsigned int max_qid = 0;
  double max_energy = 0.0;
  for( const auto &v: state->case_queue ) {
    const double cur_energy = state->CheckBorderEdge( *v );
    if( cur_energy > max_energy ) {
      max_energy = cur_energy;
      max_qid = v->qid;
    }
  }

  BOOST_CHECK_EQUAL( max_qid, testcase->qid );

  BOOST_TEST_CHECKPOINT("done");
}
