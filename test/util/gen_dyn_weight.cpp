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
#define BOOST_TEST_MODULE util.gen_dyn_weight
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/test/unit_test.hpp>
#include <boost/phoenix.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/fusion/container/vector.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/map_file.hpp>

#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/utils/count_regular_files.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/kscheduler/gen_dyn_weight.hpp"
#include "fuzzuf/utils/copy.hpp"
#include "config.h"

BOOST_AUTO_TEST_CASE(ExecuteAFLKSchedulerFromCLI) {
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
  {
    std::fstream fd( ( root_dir/"cur_coverage" ).c_str(), std::ios::out );
    fd << "2 3" << std::endl;
  } 
  {
    std::fstream fd( ( root_dir/"signal" ).c_str(), std::ios::out );
    fd << "1" << std::endl;
  } 

  unsigned int seconds = 0u;
  while( !fs::exists( ( root_dir/"dyn_katz_cent" ).c_str() ) ) {
    sleep( 1 );
    ++seconds;
    if( seconds > 20 ) {
      BOOST_ERROR("timeout");
      return;
    }
  }
  {
    const auto range = fuzzuf::utils::map_file( ( root_dir/"dyn_katz_cent" ).c_str(), O_RDONLY, true );
    auto iter = range.begin();
    const auto end = range.end();
    std::vector< boost::fusion::vector< std::uint32_t, double > > temp;
    namespace qi = boost::spirit::qi;
    if (!qi::parse(iter, end,
                   qi::skip( qi::standard::blank )[ qi::uint_ >> qi::double_ ] % qi::eol >> qi::omit[ *qi::standard::space ],
                   temp) ||
        iter != end) {
      BOOST_ERROR("unexpected dyn_katz_cent");
    }
    BOOST_CHECK( !temp.empty() );
    for( const auto &v: temp ) {
      BOOST_CHECK( boost::fusion::at_c< 0 >( v ) != 2u );
      BOOST_CHECK( boost::fusion::at_c< 0 >( v ) != 3u );
    }
  }
  BOOST_TEST_CHECKPOINT("done");
}
