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

#include <nlohmann/json.hpp>
#include "fuzzuf/algorithms/afl/afl_testcase.hpp"

namespace fuzzuf::algorithm::afl {

void to_json( nlohmann::json &dest, const AFLTestcase &src ) {
  dest = nlohmann::json::object();
  dest[ "cal_failed" ] = bool( src.cal_failed );
  dest[ "trim_done" ] = src.trim_done;
  dest[ "was_fuzzed" ] = src.was_fuzzed;
  dest[ "was_fuzzed2" ] = src.was_fuzzed;
  dest[ "passed_det" ] = src.passed_det;
  dest[ "has_new_cov" ] = src.has_new_cov;
  dest[ "var_behavior" ] = src.var_behavior;
  dest[ "favored" ] = src.favored;
  dest[ "cnt_free_cksum_dup" ] = src.cnt_free_cksum_dup;
  dest[ "fs_redundant" ] = src.fs_redundant;
  dest[ "qid" ] = src.qid;
  dest[ "bitmap_size" ] = src.bitmap_size;
  dest[ "fuzz_level" ] = src.fuzz_level;
  dest[ "cnt_free_cksum" ] = src.cnt_free_cksum;
  dest[ "exec_cksum" ] = src.exec_cksum;
  dest[ "init_perf_score" ] = src.init_perf_score;
  dest[ "exec_us" ] = src.exec_us;
  dest[ "handicap" ] = src.handicap;
  dest[ "depth" ] = src.depth;
  dest[ "tc_ref" ] = src.tc_ref;
  dest[ "border_edge" ] = src.border_edge;
  dest[ "border_edge_cnt" ] = src.border_edge_cnt;
  dest[ "thres_energy" ] = src.thres_energy;
}

}

