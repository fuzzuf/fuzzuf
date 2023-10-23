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

