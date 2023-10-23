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
#pragma once

#include <cstdio>
#include <sys/ioctl.h>
#include <cmath>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/types.h>

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/afl_macro.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_setting.hpp"
#include "fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/executor/afl_executor_interface.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/kscheduler/load_katz_centrality.hpp"
#include "fuzzuf/utils/kscheduler/load_border_edges.hpp"
#include "fuzzuf/utils/kscheduler/load_child_node.hpp"

namespace fuzzuf::algorithm::afl {

// FIXME: check if we are initializing all the members that need to be
// initialized
template <class Testcase>
AFLStateTemplate<Testcase>::AFLStateTemplate(
    std::shared_ptr<const AFLSetting> setting,
    std::shared_ptr<executor::AFLExecutorInterface> executor,
    std::unique_ptr<optimizer::HavocOptimizer>&& _havoc_optimizer)
    : setting(setting),
      executor(executor),
      input_set(),
      rand_fd(utils::OpenFile("/dev/urandom", O_RDONLY | O_CLOEXEC)),
      // This is a temporary implementation. Change the implementation properly
      // if the value need to be specified from user side.
      cpu_core_count(utils::GetCpuCore()),
      cpu_aff(utils::BindCpu(cpu_core_count, setting->cpuid_to_bind)),
      havoc_optimizer(std::move(_havoc_optimizer)),
      should_construct_auto_dict(false) {

  LoadCentralityFile();

  if (in_bitmap.empty())
    virgin_bits.assign(option::GetMapSize<Tag>(), 255);
  else {
    ReadBitmap(in_bitmap);
  }

  /* Gnuplot output file. */

  auto plot_fn = setting->out_dir / "plot_data";
  plot_file = fopen(plot_fn.c_str(), "w");
  if (!plot_file) ERROR("Unable to create '%s'", plot_fn.c_str());

  fprintf(plot_file,
          "# relative_time, cycles_done, cur_path, paths_total, "
          "pending_total, pending_favs, map_size, unique_crashes, "
          "unique_hangs, max_depth, execs_per_sec, total_execs, edges_found\n");

  if constexpr ( option::EnableKScheduler<Tag>() ) {
    {
      int fd = open( ( setting->out_dir / "edge_weight" ).c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0) ERROR("Unable to create '%s'", ( setting->out_dir / "edge_weight" ).c_str());
      edge_weight_file = fdopen(fd, "w");
    }
    {
      int fd = open( ( setting->out_dir / "scheudle_log" ).c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0) ERROR("Unable to create '%s'", ( setting->out_dir / "scheudle_log" ).c_str());
      sched_log_file = fdopen(fd, "w");
    }
    {
      int fd = open( ( setting->out_dir / "edge_log" ).c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0) ERROR("Unable to create '%s'", ( setting->out_dir / "edge_log" ).c_str());
      edge_log_file = fdopen(fd, "w");
    }
  }
}

template <class Testcase>
AFLStateTemplate<Testcase>::~AFLStateTemplate() {
  if (rand_fd != -1) {
    fuzzuf::utils::CloseFile(rand_fd);
    rand_fd = -1;
  }

  fclose(plot_file);
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    fclose(edge_weight_file); 
    fclose(sched_log_file); 
    fclose(edge_log_file); 
  }
}

template <class Testcase>
feedback::InplaceMemoryFeedback
AFLStateTemplate<Testcase>::RunExecutorWithClassifyCounts(
    const u8* buf, u32 len, feedback::ExitStatusFeedback& exit_status,
    u32 tmout) {
  total_execs++;

  if (tmout == 0) {
    executor->Run(buf, len);
  } else {
    executor->Run(buf, len, tmout);
  }

  auto inp_feed = executor->GetAFLFeedback();
  exit_status = executor->GetExitStatusFeedback();

  if constexpr (sizeof(size_t) == 8) {
    inp_feed.ModifyMemoryWithFunc([this](u8* trace_bits, u32 /* map_size */) {
      if constexpr ( !option::EnableSequentialID<Tag>() ) {
        if( enable_sequential_id ) {
          afl::util::ClassifyCounts<u64>((u64*)trace_bits,
                                     num_edge + 8u);
	}
	else {
          afl::util::ClassifyCounts<u64>((u64*)trace_bits,
                                     option::GetMapSize<Tag>());
	}
      }
      else {
        afl::util::ClassifyCounts<u64>((u64*)trace_bits,
                                   option::GetMapSize<Tag>());
      }
    });
  } else {
    inp_feed.ModifyMemoryWithFunc([this](u8* trace_bits, u32 /* map_size */) {
      if constexpr ( !option::EnableSequentialID<Tag>() ) {
        if( enable_sequential_id ) {
          afl::util::ClassifyCounts<u32>((u32*)trace_bits,
                                     num_edge + 8u);
	}
	else {
          afl::util::ClassifyCounts<u32>((u32*)trace_bits,
                                     option::GetMapSize<Tag>());
	}
      }
      else {
        afl::util::ClassifyCounts<u32>((u32*)trace_bits,
                                   option::GetMapSize<Tag>());
      }
    });
  }

  return feedback::InplaceMemoryFeedback(std::move(inp_feed));
}

#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-parameter"
#endif
template <class Testcase>
feedback::PUTExitReasonType
AFLStateTemplate<Testcase>::CalibrateCaseWithFeedDestroyed(
    Testcase& testcase, const u8* buf, u32 len,
    feedback::InplaceMemoryFeedback& inp_feed,
    feedback::ExitStatusFeedback& exit_status, u32 handicap, bool from_queue, bool increment_hit_bits) {
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
  std::array<u8, option::GetMapSize<Tag>()> first_trace;

  bool first_run = testcase.exec_cksum == 0;

  s32 old_sc = stage_cur;
  s32 old_sm = stage_max;
  std::string old_sn = std::move(stage_name);

  u32 use_tmout;
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    /* Be a bit more generous about timeouts when resuming sessions, or when
       trying to calibrate already-added finds. This helps avoid trouble due
       to intermittent latency. */
    use_tmout = setting->exec_timelimit_ms;
  }
  if (!from_queue || resuming_fuzz) {
    use_tmout = std::max(
        setting->exec_timelimit_ms + option::GetCalTmoutAdd(*this),
        setting->exec_timelimit_ms * option::GetCalTmoutPerc(*this) / 100);
  } else {
    use_tmout = setting->exec_timelimit_ms;
  }

  testcase.cal_failed++;

  stage_name = "calibration";
  stage_max = fast_cal ? 3 : option::GetCalCycles(*this);

  if constexpr ( option::EnableKScheduler<Tag>() ) {
    /* Make sure the forkserver is up before we do anything, and let's not
       count its spin-up time toward binary calibration. */
    /*if (setting->dumb_mode != 1 && !no_forkserver && !forksrv_pid) {
      init_forkserver(argv);
    }*/
    
    feedback::InplaceMemoryFeedback::DiscardActive(std::move(inp_feed));
    inp_feed = RunExecutorWithClassifyCounts(buf, len, exit_status, use_tmout);

    std::array<u8, option::GetMapSize<Tag>()> cnt_free_trace = { 0 };
    if (testcase.cnt_free_cksum == 0){
      inp_feed.ShowMemoryToFunc([&](const u8* trace_bits,
                                                           u32 map_size) {
	if( trace_bits ) {
          std::copy(
            trace_bits,
            std::next( trace_bits, std::min( option::GetMapSize<Tag>(), map_size ) ),
            cnt_free_trace.data()
          );
	}
	else {
	  std::fill(
            cnt_free_trace.begin(),
	    cnt_free_trace.end(),
	    0
          );
	}
      });
      if constexpr (sizeof(std::size_t) == 8) {
        if constexpr ( !option::EnableSequentialID<Tag>() ) {
          if( enable_sequential_id ) {
            util::SimplifyTrace< u64 >( reinterpret_cast< u64* >( cnt_free_trace.data() ), num_edge + 8u );
	  }
	  else {
            util::SimplifyTrace< u64 >( reinterpret_cast< u64* >( cnt_free_trace.data() ), option::GetMapSize<Tag>() );
	  }
	}
	else {
          util::SimplifyTrace< u64 >( reinterpret_cast< u64* >( cnt_free_trace.data() ), option::GetMapSize<Tag>() );
	}
      }
      else {
        if constexpr ( !option::EnableSequentialID<Tag>() ) {
          if( enable_sequential_id ) {
            util::SimplifyTrace< u32 >( reinterpret_cast< u32* >( cnt_free_trace.data() ), num_edge + 8u );
	  }
	  else {
            util::SimplifyTrace< u32 >( reinterpret_cast< u32* >( cnt_free_trace.data() ), option::GetMapSize<Tag>() );
	  }
	}
	else {
          util::SimplifyTrace< u32 >( reinterpret_cast< u32* >( cnt_free_trace.data() ), option::GetMapSize<Tag>() );
	}
      }
      testcase.cnt_free_cksum = inp_feed.CalcCksum32();
      
      /* check current seed's bitmap hash is dupliacted or not. */
      u32 cur_cnt_free_cksum = testcase.cnt_free_cksum;
      bool found_dup = false;
      for (u32 cksum_idx = 0u; cksum_idx < cnt_free_cksum_cnt; cksum_idx++) {
        if(cur_cnt_free_cksum == cnt_free_cksum_cache[cksum_idx]){
          /* mark duplicated cksum, skip this seed later */
          testcase.cnt_free_cksum_dup = 1;
          found_dup = true;
          break;
        }
      }
      /* save unique cksum */
      if (!found_dup){
        cnt_free_cksum_cache[cnt_free_cksum_cnt] = cur_cnt_free_cksum;
        cnt_free_cksum_cnt += 1;
        testcase.cnt_free_cksum_dup = 0;
      }
    }
  }
  

  u8 hnb = 0;
  u8 new_bits = 0;
  if (testcase.exec_cksum) {
    inp_feed.ShowMemoryToFunc([this, &first_trace, &hnb](const u8* trace_bits,
                                                         u32 /* map_size */) {
      std::memcpy(first_trace.data(), trace_bits, option::GetMapSize<Tag>());
      if constexpr ( !option::EnableSequentialID<Tag>() ) {
        if( enable_sequential_id ) {
          hnb = HasNewBits(trace_bits, &virgin_bits[0], num_edge + 8u );
        }
        else {
          hnb = HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
        }
      }
      else {
        hnb = HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
      }
    });

    if (hnb > new_bits) new_bits = hnb;
  }

  bool var_detected = false;
  u64 start_us = fuzzuf::utils::GetCurTimeUs();
  u64 stop_us;
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    if (!first_run && stage_cur % stats_update_freq == 0) {
      ShowStats();
    }

    feedback::InplaceMemoryFeedback::DiscardActive(std::move(inp_feed));
    inp_feed = RunExecutorWithClassifyCounts(buf, len, exit_status, use_tmout);

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || exit_status.exit_reason != crash_mode) {
      goto abort_calibration;  // FIXME: goto
    }

    if constexpr ( option::EnableKScheduler<Tag>() ) {
      if (!setting->dumb_mode && !stage_cur && !inp_feed.CountNonZeroBytes()) {
        exit_status.exit_reason = feedback::PUTExitReasonType::FAULT_NOINST;
        goto abort_calibration;
      }
    }

    u32 cksum = inp_feed.CalcCksum32();

    if (testcase.exec_cksum != cksum) {
      if constexpr ( option::EnableKScheduler<Tag>() ) {
        /* increment hit bits*/
        if( increment_hit_bits ) {
          IncrementHitBits( inp_feed );
	}
      }
      inp_feed.ShowMemoryToFunc([this, &hnb](const u8* trace_bits,
                                             u32 /* map_size */) {
        if constexpr ( !option::EnableSequentialID<Tag>() ) {
          if( enable_sequential_id ) {
            hnb =
                HasNewBits(trace_bits, &virgin_bits[0], num_edge + 8u);
          }
          else {
            hnb =
                HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
	  }
        }
        else {
          hnb =
              HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
        }
      });

      if (hnb > new_bits) new_bits = hnb;

      if (testcase.exec_cksum) {
        inp_feed.ShowMemoryToFunc(
            [this, &first_trace](const u8* trace_bits, u32 /* map_size */) {
              for (u32 i = 0; i < option::GetMapSize<Tag>(); i++) {
                if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {
                  var_bytes[i] = 1;
                  stage_max = option::GetCalCyclesLong(*this);
                }
              }
            });

        var_detected = true;
      } else {
        testcase.exec_cksum = cksum;
        inp_feed.ShowMemoryToFunc(
            [&first_trace](const u8* trace_bits, u32 /* map_size */) {
              std::memcpy(first_trace.data(), trace_bits,
                          option::GetMapSize<Tag>());
            });
      }
    }
  }

  stop_us = fuzzuf::utils::GetCurTimeUs();

  total_cal_us += stop_us - start_us;
  total_cal_cycles += stage_max;

  testcase.exec_us = (stop_us - start_us) / stage_max;
  if(avg_us_fast == 0){
    total_cal_us_fast += testcase.exec_us;
    total_cal_cycles_fast += 1;
    avg_us_fast = total_cal_us_fast / total_cal_cycles_fast;
  }
  else{
    if (testcase.exec_us <= 4 * avg_us_fast){
      total_cal_us_fast += testcase.exec_us;
      total_cal_cycles_fast += 1;
      avg_us_fast = total_cal_us_fast / total_cal_cycles_fast;
    }
  }
  testcase.bitmap_size = inp_feed.CountNonZeroBytes();
  testcase.handicap = handicap;
  testcase.cal_failed = 0;

  total_bitmap_size += testcase.bitmap_size;
  total_bitmap_entries++;

  UpdateBitmapScore(testcase, inp_feed);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!setting->dumb_mode && first_run &&
      exit_status.exit_reason == feedback::PUTExitReasonType::FAULT_NONE &&
      new_bits == 0) {
    exit_status.exit_reason = feedback::PUTExitReasonType::FAULT_NOBITS;
  }

abort_calibration:

  if (new_bits == 2 && !testcase.has_new_cov) {
    testcase.has_new_cov = true;
    queued_with_cov++;
  }

  /* Mark variable paths. */

  if (var_detected) {
    if constexpr ( !option::EnableSequentialID<Tag>() ) {
      if( enable_sequential_id ) {
        var_byte_count = fuzzuf::utils::CountBytes(&var_bytes[0], num_edge + 8u );
      }
      else {
        var_byte_count = fuzzuf::utils::CountBytes(&var_bytes[0], var_bytes.size() );
      }
    }
    else {
      var_byte_count = fuzzuf::utils::CountBytes(&var_bytes[0], var_bytes.size() );
    }
    if (!testcase.var_behavior) {
      MarkAsVariable(testcase);
      queued_variable++;
    }
  }

  stage_name = old_sn;
  stage_cur = old_sc;
  stage_max = old_sm;

  if (!first_run) ShowStats();

  return exit_status.exit_reason;
}

// Difference with AFL's add_to_queue:
// if buf is not nullptr, then this function saves "buf" in a file specified by
// "fn"

template <class Testcase>
std::shared_ptr<Testcase> AFLStateTemplate<Testcase>::AddToQueue(
    const std::string& fn, const u8* buf, u32 len, bool passed_det) {
  auto input = input_set.CreateOnDisk(fn);
  if (buf) {
    input->OverwriteThenUnload(buf, len);
  }

  std::shared_ptr<Testcase> testcase(new Testcase(std::move(input)));

  testcase->depth = cur_depth + 1;
  testcase->passed_det = passed_det;
  testcase->qid = queued_paths;

  if (testcase->depth > max_depth) max_depth = testcase->depth;

  if constexpr ( std::is_convertible_v< Testcase, AFLTestcase > ) {
    if constexpr ( option::EnableVerboseDebugLog< Tag >() ) {
      DEBUG( "%s", ( std::string( "Insert testcase " ) + nlohmann::json( testcase ).dump() ).c_str() )
    }
  }
  case_queue.emplace_back(testcase);

  queued_paths++;
  pending_not_fuzzed++;
  cycles_wo_finds = 0;
  last_path_time = fuzzuf::utils::GetCurTimeMs();

  return testcase;
}

template <class Testcase>
int AFLStateTemplate<Testcase>::SearchBorderEdgeId( u32 parent, u32 child ) {
  int l = 0;
  int h = num_border_edge - 1 ;
  int mid;
  int first_idx = 0;
  int last_idx = num_border_edge - 1;
  // binary search to find the first matching idx of parent node
  while (l <= h){
    mid = (int)((l+h)/2);
    if (border_edge_parent[mid] > parent){
      h = mid - 1;
      last_idx = mid;
    }
    else if (border_edge_parent[mid] < parent)
      l = mid + 1;
    else{
      first_idx = mid;
      h = mid - 1;
    }
  }

  // binary search to find the last matching idx of parent node
  l = first_idx;
  h = last_idx;
  while (l <= h){
    mid = (int)((l+h)/2);
    if (border_edge_parent[mid] > parent)
      h = mid - 1;
    else{
      last_idx = mid;
      l = mid + 1;
    }
  }

  // bin search to find the matching idx for child node from range(first_idx, last_idx)
  l = first_idx;
  h = last_idx;
  while (l <= h){
    mid = (int)((l+h)/2);
    if (border_edge_child[mid] > child)
      h = mid - 1;
    else if (border_edge_child[mid] < child)
      l = mid + 1;
    else
      return mid;
  }
  return -1;
}

template <class Testcase>
void AFLStateTemplate<Testcase>::UpdateBitmapScoreWithRawTrace(
    Testcase& testcase, const u8* trace_bits, u32 map_size) {
  const u32 count = map_size;
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    u32 i;
    u32 local_border_edge_cnt = 0;
 
    static int dbg_func_hit_cnt = 0;
    dbg_func_hit_cnt += 1;
 
    /* free child_list if not null */
    testcase.border_edge.clear();
  
    std::fill( local_border_edge_id.begin(), local_border_edge_id.end(), 0 );
    for (i = 0; i < count; i++) {
      if (trace_bits[i] && !node_child_list[i].empty()) {
        // skip non-branching node
        if (node_child_list[i].size() < 2) continue;
        // loop all children node of the triggerd parent node
        for( std::size_t j = 0; j != node_child_list[ i ].size(); ++j ) {
          // children node not triggered before, find an border edge (i, child_node), then search its corresponding borderedge ID
          int child_node = node_child_list[i][j];
          if(virgin_bits[child_node] == 0xff){
            local_border_edge_id[local_border_edge_cnt] = SearchBorderEdgeId(i, child_node);
            if( local_border_edge_id[ local_border_edge_cnt ] == static_cast< u32 >( -1 ) ) {
              printf("search_border_edge_id error\n");
              exit(0);
            }
            local_border_edge_cnt+=1;
          }
        }
      }
    }
    testcase.border_edge_cnt = local_border_edge_cnt;
    testcase.border_edge.reserve( local_border_edge_cnt );
    for (i=0; i < local_border_edge_cnt; i++){
      testcase.border_edge.push_back( local_border_edge_id[i] );
    }
  }
  else {
    u64 fav_factor = testcase.exec_us * testcase.input->GetLen();
 
    for (u32 i = 0; i < map_size; i++) {
      if (trace_bits[i]) {
        if (top_rated[i]) {
          auto& top_testcase = top_rated[i].value().get();
          u64 factor = top_testcase.exec_us * top_testcase.input->GetLen();
          if (fav_factor > factor) continue;
 
          /* Looks like we're going to win. Decrease ref count for the
             previous winner, discard its trace_bits[] if necessary. */
          --top_testcase.tc_ref;
          if (top_testcase.tc_ref == 0) {
            top_testcase.trace_mini.reset();
          }
        }
 
        /* Insert ourselves as the new winner. */
 
        top_rated[i] = std::ref(testcase);
        testcase.tc_ref++;
 
        if (!testcase.trace_mini) {
          testcase.trace_mini.reset(new std::bitset<option::GetMapSize<Tag>()>());
 
          auto& trace_mini = *testcase.trace_mini;
          for (u32 j = 0; j < count; j++) {
            trace_mini[j] = trace_bits[j] != 0;
          }
        }
 
        score_changed = true;
      }
    }
  }
}

template <class Testcase>
void AFLStateTemplate<Testcase>::UpdateBitmapScore(
    Testcase& testcase, const feedback::InplaceMemoryFeedback& inp_feed) {
  inp_feed.ShowMemoryToFunc(
      [this, &testcase](const u8* trace_bits, u32 /* map_size */) {
        u32 count = option::GetMapSize<Tag>();
        if constexpr ( !option::EnableSequentialID<Tag>() ) {
          if( enable_sequential_id ) {
            count = num_edge + 2u;
          }
        }
        UpdateBitmapScoreWithRawTrace(testcase, trace_bits,
                                      count);
      });
}

// pre-compute weight for each border edge and cache the result into a table
template <class Testcase>
void AFLStateTemplate<Testcase>::ComputeMathCache(){
  double sum = 0.0;
  int cnt = 0;

  nonzero_border_edge_weight.resize( option::GetMapSize<Tag>() >> 2 );
  std::fill( nonzero_border_edge_weight.begin(), nonzero_border_edge_weight.end(), 0 );

  //clean all old log
  assert( ftruncate(fileno(edge_weight_file), 0) == 0 );

  for( u32 i = 0u; i != num_border_edge; ++i ) {

    int parent = border_edge_parent[i];
    if (hit_bits[parent] == 0){
      border_edge_weight[i] = 0.0;
      continue;
    }
    // parent node not hit, skip
    if (virgin_bits[parent] == 0xff){
      border_edge_weight[i] = 0.0; 
      continue;
    }
    //child node hit already hit, skip 
    int child = border_edge_child[i];
    if (virgin_bits[child] != 0xff){
      border_edge_weight[i] = 0.0;
      continue;
    }

    if(std::fpclassify(katz_weight[child]) == FP_ZERO){
      border_edge_weight[i] = 0.0;
      continue;
    }

    double tmp_edge_weight = katz_weight[child] / sqrt(hit_bits[parent]);
    border_edge_weight[i] = tmp_edge_weight;
    nonzero_border_edge_weight[cnt] = tmp_edge_weight;
    cnt += 1;
    sum += tmp_edge_weight;

    std::string serialized = "border edge weight(1000X) ";
    serialized += std::to_string( i );
    serialized += ", ";
    serialized += std::to_string( tmp_edge_weight * 1000 );
    serialized += ", ";
    serialized += std::to_string( katz_weight[child] );
    serialized += ", ";
    serialized += std::to_string( sqrt(hit_bits[parent] ) );
    serialized += "\n";
    fwrite( serialized.data(), sizeof( char ), serialized.size(), edge_weight_file );
    fflush( edge_weight_file );
  }

  // This branch does not exist in original implementation, yet required to run K-Scheduler properly in first 2 min.
  if( cnt != 0 ) {
    scale_factor = 1/(sum/cnt)/adjust_rate;
  }
  else {
    scale_factor = 1/adjust_rate;
  }

  //Only consider top 50% or at most top 512 border edges into weight computation.
  std::sort(
    nonzero_border_edge_weight.begin(),
    nonzero_border_edge_weight.end()
  );

  int thres_idx = cnt * pass_rate/10;
  if (cnt-thres_idx > 512) thres_idx = cnt-512;

  border_edge_weight_threshold = nonzero_border_edge_weight[thres_idx];
  return;
}

// reload katz centrality 
template <class Testcase>
void AFLStateTemplate<Testcase>::ReloadCentralityFile(){
  // if file not exit, just return
  if( !fs::exists( "dyn_katz_cent" ) ) {
    return;
  }
  
  try {
    std::fill( katz_weight.begin(), katz_weight.end(), 0 );
    for( const auto &[idx,ret]: utils::kscheduler::LoadKatzCentrality( "dyn_katz_cent" ) ) {
      katz_weight[idx] = ret;
    }
  }
  catch( ... ) {
    perror("dyn_katz_cent open failed \n");
    std::exit(0);
  }
}

// identify border edge and compute energy
template <class Testcase>
double AFLStateTemplate<Testcase>::CheckBorderEdge(const Testcase &q) {
  double total_energy = 0.0;
  for( std::size_t i = 0; i != q.border_edge.size(); ++i ) {
    int border_edge_idx = q.border_edge[i];
    int child = border_edge_child[border_edge_idx];
    // check border edge is still not triggered
    if (virgin_bits[child] == 0xff){
      double tmp_edge_weight =  border_edge_weight[border_edge_idx];
      // add nonzero border edge weight
      if (std::fpclassify(tmp_edge_weight) != FP_ZERO){
        total_energy += tmp_edge_weight;
      }
      // check if zero borde edge weight is new, or just zero weight
      else{
        int parent = border_edge_parent[border_edge_idx];
        // new border edge
        if ((std::fpclassify(katz_weight[child]) != FP_ZERO) && (virgin_bits[child] == 0xff) && (hit_bits[parent] > 0)){

          tmp_edge_weight = katz_weight[child] / sqrt(hit_bits[parent]);
          border_edge_weight[border_edge_idx] = tmp_edge_weight;

          total_energy += tmp_edge_weight;
        }
      }
    }
  }
  return total_energy;
}

template <class Testcase>
bool AFLStateTemplate<Testcase>::SaveIfInteresting(
    const u8* buf, u32 len, feedback::InplaceMemoryFeedback& inp_feed,
    feedback::ExitStatusFeedback& exit_status) {
  bool keeping = false;

  std::string fn;
  if (exit_status.exit_reason == crash_mode) {
    if constexpr ( option::EnableKScheduler<Tag>() ) {
      /* increment hit bits*/
      IncrementHitBits( inp_feed );
    }

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    u8 hnb;

    inp_feed.ShowMemoryToFunc([this, &hnb](const u8* trace_bits,
                                           u32 /* map_size */) {
      if constexpr ( !option::EnableSequentialID<Tag>() ) {
        if( enable_sequential_id ) {
          hnb = HasNewBits(trace_bits, &virgin_bits[0], num_edge + 8u);
        }
	else {
          hnb = HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
	}
      }
      else {
        hnb = HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
      }
    });

    if (!hnb) {
      if (crash_mode == feedback::PUTExitReasonType::FAULT_CRASH) {
        total_crashes++;
      }
      return false;
    }

    if (!setting->simple_files) {
      fn = fuzzuf::utils::StrPrintf(
          "%s/queue/id:%06u,%s", setting->out_dir.c_str(), queued_paths,
          routine::update::DescribeOp(*this, hnb).c_str());
    } else {
      fn = fuzzuf::utils::StrPrintf("%s/queue/id_%06u",
                                    setting->out_dir.c_str(), queued_paths);
    }

    auto testcase = AddToQueue(fn, buf, len, false);
    if (hnb == 2) {
      testcase->has_new_cov = 1;
      queued_with_cov++;
    }

    testcase->exec_cksum = inp_feed.CalcCksum32();

    // inp_feed will may be discard to start a new execution
    // in that case inp_feed will receive the new feedback
    feedback::PUTExitReasonType res = CalibrateCaseWithFeedDestroyed(
        *testcase, buf, len, inp_feed, exit_status, queue_cycle - 1, false, true);

    if (res == feedback::PUTExitReasonType::FAULT_ERROR) {
      ERROR("Unable to execute target application");
    }

    keeping = true;
  }

  switch (exit_status.exit_reason) {
    case feedback::PUTExitReasonType::FAULT_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      total_tmouts++;
      if (unique_hangs >= option::GetKeepUniqueHang(*this)) {
        // originally here "return keeping" is used, but this is clearer right?
        return false;
      }

      if (!setting->dumb_mode) {
        if constexpr (sizeof(size_t) == 8) {
          inp_feed.ModifyMemoryWithFunc([this](u8* trace_bits, u32 /* map_size */) {
            if constexpr ( !option::EnableSequentialID<Tag>() ) {
              if( enable_sequential_id ) {
	        util::SimplifyTrace<u64>((u64*)trace_bits,
                                         num_edge + 8u);
              }
	      else {
	        util::SimplifyTrace<u64>((u64*)trace_bits,
                                          option::GetMapSize<Tag>());
	      }
	    }
	    else {
	      util::SimplifyTrace<u64>((u64*)trace_bits,
                                        option::GetMapSize<Tag>());
	    }
          });
        } else {
          inp_feed.ModifyMemoryWithFunc([this](u8* trace_bits, u32 /* map_size */) {
            if constexpr ( !option::EnableSequentialID<Tag>() ) {
              if( enable_sequential_id ) {
	        util::SimplifyTrace<u32>((u32*)trace_bits,
                                         num_edge + 8u);
              }
	      else {
	        util::SimplifyTrace<u32>((u32*)trace_bits,
                                         option::GetMapSize<Tag>());
	      }
	    }
	    else {
	      util::SimplifyTrace<u32>((u32*)trace_bits,
                                       option::GetMapSize<Tag>());
	    }
          });
        }

        u8 res;
        inp_feed.ShowMemoryToFunc(
            [this, &res](const u8* trace_bits, u32 /* map_size */) {
              if constexpr ( !option::EnableSequentialID<Tag>() ) {
                if( enable_sequential_id ) {
                  res = HasNewBits(trace_bits, &virgin_tmout[0],
                                   num_edge + 8u);
		}
		else {
                  res = HasNewBits(trace_bits, &virgin_tmout[0],
                                   option::GetMapSize<Tag>());
		}
              }
	      else {
                res = HasNewBits(trace_bits, &virgin_tmout[0],
                                 option::GetMapSize<Tag>());
	      }
            });

        if constexpr ( option::EnableKScheduler<Tag>() ) {
          IncrementHitBits( inp_feed );
	}

        if (!res) {
          // originally here "return keeping" is used, but this is clearer
          // right?
          return false;
        }
      }

      unique_tmouts++;

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (setting->exec_timelimit_ms < hang_tmout) {
        // discard inp_feed here because we will use executor
        feedback::InplaceMemoryFeedback::DiscardActive(std::move(inp_feed));
        inp_feed =
            RunExecutorWithClassifyCounts(buf, len, exit_status, hang_tmout);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!stop_soon && exit_status.exit_reason ==
                              feedback::PUTExitReasonType::FAULT_CRASH) {
          goto keep_as_crash;  // FIXME: goto
        }

        if (stop_soon || exit_status.exit_reason !=
                             feedback::PUTExitReasonType::FAULT_TMOUT) {
          return false;
        }
      }

      if (!setting->simple_files) {
        fn = fuzzuf::utils::StrPrintf(
            "%s/hangs/id:%06llu,%s", setting->out_dir.c_str(), unique_hangs,
            routine::update::DescribeOp(*this, 0).c_str());
      } else {
        fn = fuzzuf::utils::StrPrintf("%s/hangs/id_%06llu",
                                      setting->out_dir.c_str(), unique_hangs);
      }

      unique_hangs++;
      last_hang_time = fuzzuf::utils::GetCurTimeMs();
      break;

    case feedback::PUTExitReasonType::FAULT_CRASH:
    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      total_crashes++;

      if (unique_crashes >= option::GetKeepUniqueCrash(*this)) {
        // unlike FAULT_TMOUT case, keeping can be true when "crash mode" is
        // enabled
        return keeping;
      }

      if (!setting->dumb_mode) {
        if constexpr (sizeof(size_t) == 8) {
          inp_feed.ModifyMemoryWithFunc([this](u8* trace_bits, u32 /* map_size */) {
            if constexpr ( !option::EnableSequentialID<Tag>() ) {
              if( enable_sequential_id ) {
                util::SimplifyTrace<u64>((u64*)trace_bits,
                                          num_edge + 8u);
              }
              else {
                util::SimplifyTrace<u64>((u64*)trace_bits,
                                          option::GetMapSize<Tag>());
              }
            }
            else {
              util::SimplifyTrace<u64>((u64*)trace_bits,
                                        option::GetMapSize<Tag>());
            }
          });
        } else {
          inp_feed.ModifyMemoryWithFunc([this](u8* trace_bits, u32 /* map_size */) {
            if constexpr ( !option::EnableSequentialID<Tag>() ) {
              if( enable_sequential_id ) {
                util::SimplifyTrace<u32>((u32*)trace_bits,
                                          num_edge + 8u);
              }
	      else {
                util::SimplifyTrace<u32>((u32*)trace_bits,
                                          option::GetMapSize<Tag>());
	      }
	    }
	    else {
              util::SimplifyTrace<u32>((u32*)trace_bits,
                                        option::GetMapSize<Tag>());
	    }
          });
        }

        u8 res;
        inp_feed.ShowMemoryToFunc(
            [this, &res](const u8* trace_bits, u32 /* map_size */) {
              if constexpr ( !option::EnableSequentialID<Tag>() ) {
                if( enable_sequential_id ) {
                  res = HasNewBits(trace_bits, &virgin_crash[0],
                                   num_edge + 8u);
		}
		else {
                  res = HasNewBits(trace_bits, &virgin_crash[0],
                                   option::GetMapSize<Tag>());
		}
              }
	      else {
                res = HasNewBits(trace_bits, &virgin_crash[0],
                                 option::GetMapSize<Tag>());
	      }
            });
        
	if constexpr ( option::EnableKScheduler<Tag>() ) {
          IncrementHitBits( inp_feed );
	}

        if (!res) {
          // unlike FAULT_TMOUT case, keeping can be true when "crash mode" is
          // enabled
          return keeping;
        }
      }

#if 0
        if (!unique_crashes) WriteCrashReadme(); // FIXME?
#endif

      if (!setting->simple_files) {
        fn = fuzzuf::utils::StrPrintf(
            "%s/crashes/id:%06llu,sig:%02u,%s", setting->out_dir.c_str(),
            unique_crashes, exit_status.signal,
            routine::update::DescribeOp(*this, 0).c_str());
      } else {
        fn = fuzzuf::utils::StrPrintf("%s/hangs/id_%06llu_%02u",
                                      setting->out_dir.c_str(), unique_crashes,
                                      exit_status.signal);
      }

      unique_crashes++;

      last_crash_time = fuzzuf::utils::GetCurTimeMs();
      last_crash_execs = total_execs;

      break;

    case feedback::PUTExitReasonType::FAULT_ERROR:
      ERROR("Unable to execute target application");

    default:
      return keeping;
  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  int fd = fuzzuf::utils::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  fuzzuf::utils::WriteFile(fd, buf, len);
  fuzzuf::utils::CloseFile(fd);

  return keeping;
}

template <class Testcase>
double AFLStateTemplate<Testcase>::CheckTopBorderEdge(Testcase& testcase) {
  int nonzero_border_edge_cnt = 0;
  int nonzero_border_edge_thres_cnt = 0;
  testcase.thres_energy = 0.0;

  int new_border_edge = 0;
  for (u32 i = 0; i < testcase.border_edge_cnt; i++){
    int border_edge_idx = testcase.border_edge[i];
    int child = border_edge_child[border_edge_idx];
    // check border edge is still not triggered
    if (virgin_bits[child] == 0xff){
      double tmp_edge_weight =  border_edge_weight[border_edge_idx];
      // add nonzero border edge weight
      if (std::fpclassify(tmp_edge_weight) != FP_ZERO){
        nonzero_border_edge_cnt += 1;
        if (std::isgreaterequal(tmp_edge_weight, border_edge_weight_threshold)){
          nonzero_border_edge_thres_cnt += 1;
          testcase.thres_energy += tmp_edge_weight;
        }
      }
      // check if zero borde edge weight is new, or just zero weight
      else{
        int parent = border_edge_parent[border_edge_idx];
        // new border edge
        if ((std::fpclassify(katz_weight[child]) != FP_ZERO) && (virgin_bits[child] == 0xff) && (hit_bits[parent] > 0)){

          tmp_edge_weight = katz_weight[child] / sqrt(hit_bits[parent]); 
          border_edge_weight[border_edge_idx] = tmp_edge_weight;
          
	  nonzero_border_edge_cnt += 1;
          testcase.thres_energy += tmp_edge_weight;
          new_border_edge += 1;        
        }
      }
    }
  }
  nonzero_border_edge_thres_cnt += new_border_edge;


  if((nonzero_border_edge_cnt == 0) || (nonzero_border_edge_thres_cnt == 0)){
    testcase.thres_energy = 1/scale_factor;
  }

  std::string serialized;
  serialized += std::to_string( testcase.qid );
  serialized += ", ";
  serialized += std::to_string( testcase.thres_energy * scale_factor );
  serialized += ", ";
  serialized += std::to_string( nonzero_border_edge_cnt );
  serialized += ", ";
  serialized += std::to_string( nonzero_border_edge_thres_cnt );
  serialized += ", ";
  serialized += std::to_string( new_border_edge );
  fwrite( serialized.data(), sizeof( char ), serialized.size(), sched_log_file );

  return testcase.thres_energy;
}

template <class Testcase>
option::perf_type_t< typename AFLStateTemplate<Testcase>::Tag > AFLStateTemplate<Testcase>::DoCalcScore(Testcase& testcase) {
  if constexpr ( option::EnableKScheduler<Tag>() ) {
    double energy = 0.0;
    /* Adjust score based on execution speed of this path, compared to the
       global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
       less expensive to fuzz, so we're giving them more air time. */
 
    energy = testcase.init_perf_score * testcase.thres_energy * scale_factor;
 
    fprintf(sched_log_file, " %d %f || ", testcase.init_perf_score, energy);
 
    if (energy > option::GetHavocMaxMult(*this) * 100) energy = option::GetHavocMaxMult(*this) * 100;
 
    return energy;
  }
  else {
    u32 avg_exec_us = total_cal_us / total_cal_cycles;
    u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
    option::perf_type_t< Tag > perf_score = 100;
    /* Adjust score based on execution speed of this path, compared to the
       global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
       less expensive to fuzz, so we're giving them more air time. */
 
    if (testcase.exec_us * 0.1 > avg_exec_us)
      perf_score = 10;
    else if (testcase.exec_us * 0.25 > avg_exec_us)
      perf_score = 25;
    else if (testcase.exec_us * 0.5 > avg_exec_us)
      perf_score = 50;
    else if (testcase.exec_us * 0.75 > avg_exec_us)
      perf_score = 75;
    else if (testcase.exec_us * 4 < avg_exec_us)
      perf_score = 300;
    else if (testcase.exec_us * 3 < avg_exec_us)
      perf_score = 200;
    else if (testcase.exec_us * 2 < avg_exec_us)
      perf_score = 150;
 
    /* Adjust score based on bitmap size. The working theory is that better
       coverage translates to better targets. Multiplier from 0.25x to 3x. */
 
    if (testcase.bitmap_size * 0.3 > avg_bitmap_size)
      perf_score *= 3;
    else if (testcase.bitmap_size * 0.5 > avg_bitmap_size)
      perf_score *= 2;
    else if (testcase.bitmap_size * 0.75 > avg_bitmap_size)
      perf_score *= 1.5;
    else if (testcase.bitmap_size * 3 < avg_bitmap_size)
      perf_score *= 0.25;
    else if (testcase.bitmap_size * 2 < avg_bitmap_size)
      perf_score *= 0.5;
    else if (testcase.bitmap_size * 1.5 < avg_bitmap_size)
      perf_score *= 0.75;
 
    /* Adjust score based on handicap. Handicap is proportional to how late
       in the game we learned about this path. Latecomers are allowed to run
       for a bit longer until they catch up with the rest. */
 
    if (testcase.handicap >= 4) {
      perf_score *= 4;
      testcase.handicap -= 4;
    } else if (testcase.handicap) {
      perf_score *= 2;
      testcase.handicap--;
    }
 
    /* Final adjustment based on input depth, under the assumption that fuzzing
       deeper test cases is more likely to reveal stuff that can't be
       discovered with traditional fuzzers. */
 
    switch (testcase.depth) {
      case 0 ... 3:
        break;
      case 4 ... 7:
        perf_score *= 2;
        break;
      case 8 ... 13:
        perf_score *= 3;
        break;
      case 14 ... 25:
        perf_score *= 4;
        break;
      default:
        perf_score *= 5;
        break;
    }
 
    /* Make sure that we don't go over limit. */
 
    if (perf_score > option::GetHavocMaxMult(*this) * 100) {
      perf_score = option::GetHavocMaxMult(*this) * 100;
    }
 
    return perf_score;
  }
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.
   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

template <class Testcase>
u8 AFLStateTemplate<Testcase>::HasNewBits(const u8* trace_bits, u8* virgin_map,
                                          u32 map_size) {
  // we assume the word size is the same as sizeof(size_t)
  static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8);
  using UInt = std::conditional_t<sizeof(size_t) == 4, u32, u64>;

  constexpr int width = sizeof(UInt);
  constexpr int wlog = width == 4 ? 2 :
                                  /* width == 8 */ 3;

  UInt* virgin = (UInt*)virgin_map;
  const UInt* current = (const UInt*)trace_bits;

  u32 i = map_size >> wlog;

  u8 ret = 0;
  while (i--) {
    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {
      if (likely(ret < 2)) {
        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

        for (int j = 0; j < width; j++) {
          if (cur[j] && vir[j] == 0xff) {
            ret = 2;
            break;
          }
        }
        if (ret != 2) ret = 1;
      }
      *virgin &= ~*current;
    }

    current++;
    virgin++;
  }

  if (ret && virgin_map == &virgin_bits[0]) bitmap_changed = 1;

  return ret;
}

template <class Testcase>
void AFLStateTemplate<Testcase>::MarkAsDetDone(Testcase& testcase) {
  const auto& input = *testcase.input;

  std::string fn = input.GetPath().filename().string();
  fn = fuzzuf::utils::StrPrintf("%s/queue/.state/deterministic_done/%s",
                                setting->out_dir.c_str(), fn.c_str());

  int fd = fuzzuf::utils::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  fuzzuf::utils::CloseFile(fd);

  testcase.passed_det = true;
}

template <class Testcase>
void AFLStateTemplate<Testcase>::MarkAsVariable(Testcase& testcase) {
  const auto& input = *testcase.input;

  std::string fn = input.GetPath().filename().string();
  std::string ldest = fuzzuf::utils::StrPrintf("../../%s", fn.c_str());
  fn = fuzzuf::utils::StrPrintf("%s/queue/.state/variable_behavior/%s",
                                setting->out_dir.c_str(), fn.c_str());

  if (symlink(ldest.c_str(), fn.c_str()) == -1) {
    int fd = fuzzuf::utils::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    fuzzuf::utils::CloseFile(fd);
  }

  testcase.var_behavior = true;
}

template <class Testcase>
void AFLStateTemplate<Testcase>::MarkAsRedundant(Testcase& testcase, bool val) {
  const auto& input = *testcase.input;

  if (val == testcase.fs_redundant) return;

  testcase.fs_redundant = val;

  std::string fn = input.GetPath().filename().string();
  fn = fuzzuf::utils::StrPrintf("%s/queue/.state/redundant_edges/%s",
                                setting->out_dir.c_str(), fn.c_str());

  if (val) {
    int fd = fuzzuf::utils::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    fuzzuf::utils::CloseFile(fd);
  } else {
    if (unlink(fn.c_str())) ERROR("Unable to remove '%s'", fn.c_str());
  }
}

/* Get the number of runnable processes, with some simple smoothing. */

template <class State>
static double GetRunnableProcesses(State& state) {
  // FIXME: static variable
  static double res = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE* f = fopen("/proc/stat", "r");
  char tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f)) {
    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14))
      val += atoi(tmp + 14);
  }

  fclose(f);

  if (!res) {
    res = val;
  } else {
    res = res * (1.0 - 1.0 / option::GetAvgSmoothing(state)) +
          ((double)val) * (1.0 / option::GetAvgSmoothing(state));
  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;
}

/* Update stats file for unattended monitoring. */

template <class Testcase>
void AFLStateTemplate<Testcase>::WriteStatsFile(double bitmap_cvg,
                                                double stability, double eps) {
  auto fn = setting->out_dir / "fuzzer_stats";
  int fd =
      fuzzuf::utils::OpenFile(fn.string(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) ERROR("Unable to create '%s'", fn.c_str());

  FILE* f = fdopen(fd, "w");
  if (!f) ERROR("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps) {
    bitmap_cvg = last_bcvg;
    stability = last_stab;
    eps = last_eps;
  } else {
    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps = eps;
  }

  fprintf(
      f,
      "start_time        : %llu\n"
      "last_update       : %llu\n"
      "fuzzer_pid        : %u\n"
      "cycles_done       : %llu\n"
      "execs_done        : %llu\n"
      "execs_per_sec     : %0.02f\n"
      "paths_total       : %u\n"
      "paths_favored     : %u\n"
      "paths_found       : %u\n"
      "paths_imported    : %u\n"
      "max_depth         : %u\n"
      "cur_path          : %u\n" /* Must match find_start_position() */
      "pending_favs      : %u\n"
      "pending_total     : %u\n"
      "variable_paths    : %u\n"
      "stability         : %0.02f%%\n"
      "bitmap_cvg        : %0.02f%%\n"
      "unique_crashes    : %llu\n"
      "unique_hangs      : %llu\n"
      "last_path         : %llu\n"
      "last_crash        : %llu\n"
      "last_hang         : %llu\n"
      "execs_since_crash : %llu\n"
      "exec_timeout      : %u\n" /* Must match find_timeout() */
      "afl_banner        : %s\n"
      "afl_version       : %s\n"
      "target_mode       : %s%s%s%s%s%s%s\n"
      "command_line      : %s\n"
      "slowest_exec_ms   : %llu\n",
      start_time / 1000, fuzzuf::utils::GetCurTimeMs() / 1000, getpid(),
      queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps, queued_paths,
      queued_favored, queued_discovered, queued_imported, max_depth,
      current_entry, pending_favored, pending_not_fuzzed, queued_variable,
      stability, bitmap_cvg, unique_crashes, unique_hangs,
      last_path_time / 1000, last_crash_time / 1000, last_hang_time / 1000,
      total_execs - last_crash_execs, setting->exec_timelimit_ms,
      use_banner.c_str(), option::GetVersion(*this), qemu_mode ? "qemu " : "",
      setting->dumb_mode ? " dumb " : "", no_forkserver ? "no_forksrv " : "",
      crash_mode != feedback::PUTExitReasonType::FAULT_NONE ? "crash " : "",
      persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
      (qemu_mode || setting->dumb_mode || no_forkserver ||
       crash_mode != feedback::PUTExitReasonType::FAULT_NONE ||
       persistent_mode || deferred_mode)
          ? ""
          : "default",
      orig_cmdline.c_str(), slowest_exec_ms);
  /* ignore errors */

  /* Get rss value from the children
     We must have killed the forkserver process and called waitpid
     before calling getrusage */

  struct rusage usage;

  if (getrusage(RUSAGE_CHILDREN, &usage)) {
    WARNF("getrusage failed");
  } else if (usage.ru_maxrss == 0) {
    fprintf(f, "peak_rss_mb       : not available while afl is running\n");
  } else {
#ifdef __APPLE__
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 20);
#else
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 10);
#endif /* ^__APPLE__ */
  }

  fclose(f);
}

template <class Testcase>
void AFLStateTemplate<Testcase>::SaveAuto(void) {
  if (!auto_changed) return;
  auto_changed = false;

  u32 lim = std::min<u32>(option::GetUseAutoExtras(*this), a_extras.size());
  for (u32 i = 0; i < lim; i++) {
    auto fn = setting->out_dir / "queue/.state/auto_extras" /
              fuzzuf::utils::StrPrintf("auto_%06u", i);

    int fd = fuzzuf::utils::OpenFile(fn.string(), O_WRONLY | O_CREAT | O_TRUNC,
                                     0600);
    if (fd < 0) ERROR("Unable to create '%s'", fn.c_str());

    fuzzuf::utils::WriteFile(fd, &a_extras[i].data[0], a_extras[i].data.size());
    fuzzuf::utils::CloseFile(fd);
  }
}

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

template <class Testcase>
void AFLStateTemplate<Testcase>::WriteBitmap(void) {
  if (!bitmap_changed) return;
  bitmap_changed = false;

  auto fn = setting->out_dir / "fuzz_bitmap";

  int fd =
      fuzzuf::utils::OpenFile(fn.string(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) ERROR("Unable to create '%s'", fn.c_str());

  fuzzuf::utils::WriteFile(fd, virgin_bits.data(), option::GetMapSize<Tag>());
  fuzzuf::utils::CloseFile(fd);
}

/* Read bitmap from file. This is for the -B option again. */

template <class Testcase>
void AFLStateTemplate<Testcase>::ReadBitmap(fs::path fname) {
  int fd = fuzzuf::utils::OpenFile(fname.string(), O_RDONLY);
  if (fd < 0) ERROR("Unable to open '%s'", fname.c_str());

  virgin_bits.resize(option::GetMapSize<Tag>());
  fuzzuf::utils::ReadFile(fd, virgin_bits.data(), option::GetMapSize<Tag>());
  fuzzuf::utils::CloseFile(fd);
}

template <class Testcase>
void AFLStateTemplate<Testcase>::MaybeUpdatePlotFile(double bitmap_cvg,
                                                     double eps, u64 edges_found) {
  if (prev_qp == queued_paths && prev_pf == pending_favored &&
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth)
    return;

  prev_qp = queued_paths;
  prev_pf = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce = current_entry;
  prev_qc = queue_cycle;
  prev_uc = unique_crashes;
  prev_uh = unique_hangs;
  prev_md = max_depth;

  /* Fields in the file:

     relative_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec, total_execs, edges_found */

  fprintf(plot_file,
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f, %llu, %llu\n",
          (utils::GetCurTimeMs() - start_time) / 1000, queue_cycle - 1, current_entry,
          queued_paths, pending_not_fuzzed, pending_favored, bitmap_cvg,
          unique_crashes, unique_hangs, max_depth, eps, total_execs, edges_found); /* ignore errors */

  fflush(plot_file);
}

template <class Testcase>
void AFLStateTemplate<Testcase>::SaveCmdline(
    const std::vector<std::string>& argv) {
  for (u32 i = 0; i < argv.size(); i++) {
    if (i > 0) orig_cmdline += ' ';
    orig_cmdline += argv[i];
  }
}

template <class Testcase>
void AFLStateTemplate<Testcase>::FixUpBanner(const std::string& name) {
  if (use_banner.empty()) {
    if (sync_id.empty()) {
      fs::path put_path(name);
      use_banner = put_path.filename().string();
    } else {
      use_banner = sync_id;
    }
  }

  // In the original AFL, 40 is used instead of 33.
  // Because we add "fuzzuf " in the banner, we reduce this value.
  if (use_banner.size() > 33) {
    use_banner.resize(33);
    use_banner += "...";
  }
}

template <class Testcase>
void AFLStateTemplate<Testcase>::CheckIfTty(void) {
  struct winsize ws;

  if (getenv("AFL_NO_UI")) {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws)) {
    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less "
          "verbose.");
      not_on_tty = 1;
    }

    return;
  }
}

static void ShufflePtrs(void** ptrs, u32 cnt, int rand_fd) {
  for (u32 i = 0; i < cnt - 2; i++) {
    u32 j = i + util::UR(cnt - i, rand_fd);
    std::swap(ptrs[i], ptrs[j]);
  }
}

template <class Testcase>
void AFLStateTemplate<Testcase>::ReadTestcases(void) {
  // FIXME: support resume
  struct dirent** nl;

  auto& in_dir = setting->in_dir;
  ACTF("Scanning '%s'...", in_dir.c_str());

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  int nl_cnt = fuzzuf::utils::ScanDirAlpha(in_dir.string(), &nl);
  if (nl_cnt < 0) {
    MSG("\n" cLRD "[-] " cRST
        "The input directory does not seem to be valid - try again. The fuzzer "
        "needs\n"
        "    one or more test case to start with - ideally, a small file under "
        "1 kB\n"
        "    or so. The cases must be stored as regular files directly in the "
        "input\n"
        "    directory.\n");

    ERROR("Unable to open '%s'", in_dir.c_str());
  }

  if (shuffle_queue && nl_cnt > 1) {
    ACTF("Shuffling queue...");
    ShufflePtrs((void**)nl, nl_cnt, rand_fd);
  }

  for (int i = 0; i < nl_cnt; i++) {
    struct stat st;

    std::string fn =
        fuzzuf::utils::StrPrintf("%s/%s", in_dir.c_str(), nl[i]->d_name);
    std::string dfn = fuzzuf::utils::StrPrintf(
        "%s/.state/deterministic_done/%s", in_dir.c_str(), nl[i]->d_name);

    bool passed_det = false;
    free(nl[i]); /* not tracked */

    if (lstat(fn.c_str(), &st) != 0 || access(fn.c_str(), R_OK) != 0) {
      ERROR("Unable to access '%s'", fn.c_str());
    }

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size ||
        fn.find("/README.txt") != std::string::npos) {
      continue;
    }

    if (st.st_size > option::GetMaxFile<Tag>()) {
      WARNF("Test case '%s' is too big (%s, limit is %s)", fn.c_str(),
           util::DescribeMemorySize(st.st_size).c_str(),
           util::DescribeMemorySize(option::GetMaxFile<Tag>()).c_str());
      continue;
    }

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (access(dfn.c_str(), F_OK) == 0) passed_det = true;

    AddToQueue(fn, nullptr, (u32)st.st_size, passed_det);
  }

  free(nl); /* not tracked */

  if (!queued_paths) {
    MSG("\n" cLRD "[-] " cRST
        "Looks like there are no valid test cases in the input directory! The "
        "fuzzer\n"
        "    needs one or more test case to start with - ideally, a small file "
        "under\n"
        "    1 kB or so. The cases must be stored as regular files directly in "
        "the\n"
        "    input directory.\n");

    EXIT("No usable test cases in '%s'", in_dir.c_str());
  }

  last_path_time = 0;
  queued_at_start = queued_paths;
}

template <class Testcase>
void AFLStateTemplate<Testcase>::PivotInputs() {
  ACTF("Creating hard links for all input files...");

  u32 id = 0;
  for (const auto& testcase : case_queue) {
    auto& input = *testcase->input;

    std::string rsl = input.GetPath().filename().string();

    const std::string case_prefix = setting->simple_files ? "id_" : "id:";

    u32 orig_id;
    std::string nfn;
    if (rsl.substr(0, 3) == case_prefix &&
        sscanf(rsl.c_str() + 3, "%06u", &orig_id) == 1 && orig_id == id) {
      resuming_fuzz = true;
      nfn = fuzzuf::utils::StrPrintf("%s/queue/%s", setting->out_dir.c_str(),
                                     rsl.c_str());

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      u32 src_id;
      auto pos = rsl.find(':');
      if (pos != std::string::npos &&
          sscanf(rsl.c_str() + pos + 1, "%06u", &src_id) == 1) {
        if (src_id < case_queue.size()) {
          testcase->depth = case_queue[src_id]->depth + 1;
        }

        if (max_depth < testcase->depth) {
          max_depth = testcase->depth;
        }
      }
    } else {
      /* No dice - invent a new name, capturing the original one as a
         substring. */

      if (!setting->simple_files) {
        auto pos = rsl.find(",orig:");

        if (pos != std::string::npos)
          pos += 6;
        else
          pos = 0;

        nfn = fuzzuf::utils::StrPrintf("%s/queue/id:%06u,orig:%s",
                                       setting->out_dir.c_str(), id,
                                       rsl.c_str() + pos);
      } else {
        nfn = fuzzuf::utils::StrPrintf("%s/queue/id_%06u",
                                       setting->out_dir.c_str(), id);
      }
    }

    /* Pivot to the new queue entry. */

    if (!input.LinkAndRefer(nfn)) {
      input.CopyAndRefer(nfn);
    }

    /* Make sure that the passed_det value carries over, too. */

    if (testcase->passed_det) MarkAsDetDone(*testcase);

    id++;
  }

#if 0
    if (in_place_resume) NukeResumeDir();
#endif
}

/* increment hit bits by 1 for every element of trace_bits that has been hit.
 effectively counts that one input has hit each element of trace_bits */
template <class Testcase>
void AFLStateTemplate<Testcase>::IncrementHitBits(
    feedback::InplaceMemoryFeedback &inp_feed
  ){
  inp_feed.ShowMemoryToFunc([&](const u8* trace_bits, u32 /* map_size */) {
    u32 count = option::GetMapSize<Tag>();
    if constexpr ( !option::EnableSequentialID<Tag>() ) {
      if( enable_sequential_id ) {
        count = num_edge + 8u;
      }
    }
    u32 total_iters = count / sizeof( unsigned long int );
    const unsigned long int *current = reinterpret_cast< const unsigned long int* >( trace_bits );
    for (u32 i = 0; i < total_iters; ++i){ 
      if (unlikely(*current)){
        if constexpr ( sizeof( unsigned long int ) == 8u ) {
          const u8 *cur = reinterpret_cast< const u8* >( current );
          u32 base_idx = i * 8 ;
          if (cur[0])
            hit_bits[base_idx]++;
          if (cur[1])
            hit_bits[base_idx+1]++;
          if (cur[2])
            hit_bits[base_idx+2]++;
          if (cur[3])
            hit_bits[base_idx+3]++;
          if (cur[4])
            hit_bits[base_idx+4]++;
          if (cur[5])
            hit_bits[base_idx+5]++;
          if (cur[6])
            hit_bits[base_idx+6]++;
          if (cur[7])
            hit_bits[base_idx+7]++;
        }
        else if constexpr ( sizeof( unsigned long int ) == 4u ) {
          u8 *cur = reinterpret_cast< u8* >( current );
          u32 base_idx = i * 8 ;
          if (cur[0])
            hit_bits[base_idx]++;
          if (cur[1])
            hit_bits[base_idx+1]++;
          if (cur[2])
            hit_bits[base_idx+2]++;
          if (cur[3])
            hit_bits[base_idx+3]++;
        }
      }
      current++;
    }
  });
}

template <class Tag>
static void CheckMapCoverage(const feedback::InplaceMemoryFeedback& inp_feed) {
  if (inp_feed.CountNonZeroBytes() < 100) return;

  inp_feed.ShowMemoryToFunc([](const u8* trace_bits, u32 /* map_size */) {
    u32 start = 1 << (option::GetMapSizePow2<Tag>() - 1);
    for (u32 i = start; i < option::GetMapSize<Tag>(); i++) {
      if (trace_bits[i]) return;
    }

    WARNF("Recompile binary with newer version of afl to improve coverage!");
  });
}

template <class Testcase>
void AFLStateTemplate<Testcase>::PerformDryRun() {
  u32 cal_failures = 0;
  char* skip_crashes = getenv("AFL_SKIP_CRASHES");

  for (const auto& testcase : case_queue) {
    auto& input = *testcase->input;

    std::string fn = input.GetPath().filename().string();

    ACTF("Attempting dry run with '%s'...", fn.c_str());

    input.Load();

    // There should be no active instance of InplaceMemoryFeedback at this
    // point. So we can just create a temporary instance to get a result.
    feedback::InplaceMemoryFeedback inp_feed;
    feedback::ExitStatusFeedback exit_status;
    feedback::PUTExitReasonType res = CalibrateCaseWithFeedDestroyed(
        *testcase, input.GetBuf(), input.GetLen(), inp_feed, exit_status, 0,
        true, false);

    input.Unload();

    if (stop_soon) return;

    if (res == crash_mode || res == feedback::PUTExitReasonType::FAULT_NOBITS) {
      MSG(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST,
          input.GetLen(), testcase->bitmap_size, testcase->exec_us);
    }

    switch (res) {
      case feedback::PUTExitReasonType::FAULT_NONE:
        if (testcase == case_queue.front()) {
          CheckMapCoverage<typename Testcase::Tag>(inp_feed);
        }

        if (crash_mode != feedback::PUTExitReasonType::FAULT_NONE) {
          EXIT("Test case '%s' does *NOT* crash", fn.c_str());
        }

        break;

      case feedback::PUTExitReasonType::FAULT_TMOUT:

        if (timeout_given) {
          /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

          if (timeout_given > 1) {
            WARNF("Test case results in a timeout (skipping)");
            testcase->cal_failed = option::GetCalChances(*this);
            cal_failures++;
            break;
          }

          MSG("\n" cLRD "[-] " cRST
              "The program took more than %u ms to process one of the initial "
              "test cases.\n"
              "    Usually, the right thing to do is to relax the -t option - "
              "or to delete it\n"
              "    altogether and allow the fuzzer to auto-calibrate. That "
              "said, if you know\n"
              "    what you are doing and want to simply skip the unruly test "
              "cases, append\n"
              "    '+' at the end of the value passed to -t ('-t %u+').\n",
              setting->exec_timelimit_ms, setting->exec_timelimit_ms);

          EXIT("Test case '%s' results in a timeout", fn.c_str());
        } else {
          MSG("\n" cLRD "[-] " cRST
              "The program took more than %u ms to process one of the initial "
              "test cases.\n"
              "    This is bad news; raising the limit with the -t option is "
              "possible, but\n"
              "    will probably make the fuzzing process extremely slow.\n\n"

              "    If this test case is just a fluke, the other option is to "
              "just avoid it\n"
              "    altogether, and find one that is less of a CPU hog.\n",
              setting->exec_timelimit_ms);

          EXIT("Test case '%s' results in a timeout", fn.c_str());
        }

      case feedback::PUTExitReasonType::FAULT_CRASH:

        if (crash_mode == feedback::PUTExitReasonType::FAULT_CRASH) break;

        if (skip_crashes) {
          WARNF("Test case results in a crash (skipping)");
          testcase->cal_failed = option::GetCalChances(*this);
          cal_failures++;
          break;
        }

        if (setting->exec_memlimit > 0) {
          MSG("\n" cLRD "[-] " cRST
              "Oops, the program crashed with one of the test cases provided. "
              "There are\n"
              "    several possible explanations:\n\n"

              "    - The test case causes known crashes under normal working "
              "conditions. If\n"
              "      so, please remove it. The fuzzer should be seeded with "
              "interesting\n"
              "      inputs - but not ones that cause an outright crash.\n\n"

              "    - The current memory limit (%s) is too low for this "
              "program, causing\n"
              "      it to die due to OOM when parsing valid files. To fix "
              "this, try\n"
              "      bumping it up with the -m setting in the command line. If "
              "in doubt,\n"
              "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
              "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] "
              "<testcase )\n\n"
#else
              "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] "
              "<testcase )\n\n"
#endif /* ^RLIMIT_AS */

              "      Tip: you can use http://jwilk.net/software/recidivm to "
              "quickly\n"
              "      estimate the required amount of virtual memory for the "
              "binary. Also,\n"
              "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__

              "    - On MacOS X, the semantics of fork() syscalls are "
              "non-standard and may\n"
              "      break afl-fuzz performance optimizations when running "
              "platform-specific\n"
              "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the "
              "environment.\n\n"

#endif /* __APPLE__ */

              "",
              util::DescribeMemorySize(setting->exec_memlimit << 20).c_str(),
              setting->exec_memlimit - 1, "docs");
        } else {
          MSG("\n" cLRD "[-] " cRST
              "Oops, the program crashed with one of the test cases provided. "
              "There are\n"
              "    several possible explanations:\n\n"

              "    - The test case causes known crashes under normal working "
              "conditions. If\n"
              "      so, please remove it. The fuzzer should be seeded with "
              "interesting\n"
              "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__

              "    - On MacOS X, the semantics of fork() syscalls are "
              "non-standard and may\n"
              "      break afl-fuzz performance optimizations when running "
              "platform-specific\n"
              "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the "
              "environment.\n\n"

#endif /* __APPLE__ */

          );
        }

        EXIT("Test case '%s' results in a crash", fn.c_str());

      case feedback::PUTExitReasonType::FAULT_ERROR:

        EXIT("Unable to execute target application ('%s')",
             setting->argv[0].c_str());

      case feedback::PUTExitReasonType::FAULT_NOINST:

        EXIT("No instrumentation detected");

      case feedback::PUTExitReasonType::FAULT_NOBITS:

        useless_at_start++;

        if (in_bitmap.empty() && !shuffle_queue)
          WARNF("No new instrumentation output, test case may be useless.");

        break;
    }

    if (testcase->var_behavior)
      WARNF("Instrumentation output varies across runs.");
  }

  if (cal_failures) {
    if (cal_failures == queued_paths)
      EXIT("All test cases time out%s, giving up!",
           skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");
  }

  OKF("All test cases processed.");
}

/* Check terminal dimensions after resize. */

static bool CheckTermSize() {
  struct winsize ws;

  bool term_too_small = false;

  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws)) return term_too_small;

  if (ws.ws_row == 0 && ws.ws_col == 0) return term_too_small;
  if (ws.ws_row < 25 || ws.ws_col < 80) term_too_small = true;

  return term_too_small;
}

template <class Testcase>
void AFLStateTemplate<Testcase>::ShowStats(void) {
  // Lots of constants appear, so overlook this.
  using namespace afl::option;

  const u32 MAP_SIZE = GetMapSize<Tag>();

  u64 cur_ms = fuzzuf::utils::GetCurTimeMs();

  /* If not enough time has passed since last UI update, bail out. */
  if (cur_ms - last_ms < 1000 / GetUiTargetHz(*this)) return;

  /* Check if we're past the 10 minute mark. */
  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = true;

  /* Calculate smoothed exec speed stats. */
  if (last_execs == 0) {
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);
  } else {
    double cur_avg =
        ((double)(total_execs - last_execs)) * 1000 / (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */
    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec) avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / GetAvgSmoothing(*this)) +
               cur_avg * (1.0 / GetAvgSmoothing(*this));
  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */
  stats_update_freq = avg_exec / (GetUiTargetHz(*this) * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* Do some bitmap stats. */
  u32 t_bytes = 0u;
  if constexpr ( !option::EnableSequentialID<Tag>() ) {
    if( enable_sequential_id ) {
      t_bytes =
        fuzzuf::utils::CountNon255Bytes(&virgin_bits[0], num_edge + 2u );
    }
    else {
      t_bytes =
        fuzzuf::utils::CountNon255Bytes(&virgin_bits[0], virgin_bits.size() );
    }
  }
  else {
    t_bytes =
      fuzzuf::utils::CountNon255Bytes(&virgin_bits[0], virgin_bits.size() );
  }
  double t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  double stab_ratio;
  if (t_bytes)
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */
  if (cur_ms - last_stats_ms > GetStatsUpdateSec(*this) * 1000) {
    last_stats_ms = cur_ms;

    WriteStatsFile(t_byte_ratio, stab_ratio, avg_exec);
    SaveAuto();
    WriteBitmap();
  }

  /* Every now and then, write plot data. */
  if (cur_ms - last_plot_ms > GetPlotUpdateSec<Tag>() * 1000) {
    last_plot_ms = cur_ms;
    MaybeUpdatePlotFile(t_byte_ratio, avg_exec, t_bytes);
  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */
  if (!setting->dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE"))
    stop_soon = 2;

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH")) stop_soon = 2;
  

  /* If we're not on TTY, bail out. */
  if (not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */
  u32 t_bits = 0u;
  if constexpr ( !option::EnableSequentialID<Tag>() ) {
    if( enable_sequential_id ) {
      t_bits = (MAP_SIZE << 3) -
               fuzzuf::utils::CountBits(&virgin_bits[0], num_edge + 8u );
    }
    else {
      t_bits = (MAP_SIZE << 3) -
               fuzzuf::utils::CountBits(&virgin_bits[0], virgin_bits.size() );
    }
  }
  else {
    t_bits = (MAP_SIZE << 3) -
             fuzzuf::utils::CountBits(&virgin_bits[0], virgin_bits.size() );
  }

  /* Now, for the visuals... */
  bool term_too_small = false;
  if (clear_screen) {
    MSG(TERM_CLEAR);
    clear_screen = false;

    term_too_small = CheckTermSize();
  }

  MSG(TERM_HOME);

  if (term_too_small) {
    MSG(cBRI
        "Your terminal is too small to display the UI.\n"
        "Please resize terminal window to at least 80x25.\n" cRST);

    return;
  }

  // FIXME: use stringstream...?
  // anyways it's weird to mix up sprintf and std::string

  /* Let's start by drawing a centered banner. */
  u32 banner_len =
      (crash_mode != feedback::PUTExitReasonType::FAULT_NONE ? 24 : 22) +
      strlen(GetVersion(*this)) + use_banner.size();
  u32 banner_pad = (80 - banner_len) / 2;

  auto fuzzer_name = crash_mode != feedback::PUTExitReasonType::FAULT_NONE
                         ? cPIN "fuzzuf peruvian were-rabbit"
                         : cYEL "fuzzuf american fuzzy lop";

  std::string tmp(banner_pad, ' ');
  tmp += fuzzuf::utils::StrPrintf("%s " cLCY "%s" cLGN " (%s)", fuzzer_name,
                                  GetVersion(*this), use_banner.c_str());
  MSG("\n%s\n\n", tmp.c_str());

  /* Lord, forgive me this. */
  MSG(SET_G1 bSTG bLT bH bSTOP cCYA
      " process timing " bSTG bH30 bH5 bH2 bHB bH bSTOP cCYA
      " overall results " bSTG bH5 bRT "\n");

  std::string col;
  if (setting->dumb_mode) {
    col = cRST;
  } else {
    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    if (queue_cycle == 1 || min_wo_finds < 15) {
      /* First queue cycle: don't stop now! */
      col = cMGN;
    } else if (cycles_wo_finds < 25 || min_wo_finds < 30) {
      /* Subsequent cycles, but we're still making finds. */
      col = cYEL;
    } else if (cycles_wo_finds > 100 && !pending_not_fuzzed &&
               min_wo_finds > 120) {
      /* No finds for a long time and no test cases to try. */
      col = cLGN;
    } else {
      /* Default: cautiously OK to stop? */
      col = cLBL;
    }
  }

  // From here, we use these a lot...!
  using afl::util::DescribeFloat;
  using afl::util::DescribeInteger;
  using afl::util::DescribeTimeDelta;

  MSG(bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
               "  cycles done : %s%-5s  " bSTG bV "\n",
      DescribeTimeDelta(cur_ms, start_time).c_str(), col.c_str(),
      DescribeInteger(queue_cycle - 1).c_str());

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!setting->dumb_mode &&
      (last_path_time || resuming_fuzz || queue_cycle == 1 ||
       !in_bitmap.empty() ||
       crash_mode != feedback::PUTExitReasonType::FAULT_NONE)) {
    MSG(bV bSTOP "   last new path : " cRST "%-34s ",
        DescribeTimeDelta(cur_ms, last_path_time).c_str());

  } else {
    if (setting->dumb_mode) {
      MSG(bV bSTOP "   last new path : " cPIN "n/a" cRST
                   " (non-instrumented mode)        ");
    } else {
      MSG(bV bSTOP "   last new path : " cRST "none yet " cLRD
                   "(odd, check syntax!)      ");
    }
  }

  MSG(bSTG bV bSTOP "  total paths : " cRST "%-5s  " bSTG bV "\n",
      DescribeInteger(queued_paths).c_str());

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  tmp = DescribeInteger(unique_crashes);
  if (unique_crashes >= GetKeepUniqueCrash(*this)) tmp += '+';

  MSG(bV bSTOP " last uniq crash : " cRST "%-34s " bSTG bV bSTOP
               " uniq crashes : %s%-6s " bSTG bV "\n",
      DescribeTimeDelta(cur_ms, last_crash_time).c_str(),
      unique_crashes ? cLRD : cRST, tmp.c_str());

  tmp = DescribeInteger(unique_hangs);
  if (unique_hangs >= GetKeepUniqueHang(*this)) tmp += '+';

  MSG(bV bSTOP "  last uniq hang : " cRST "%-34s " bSTG bV bSTOP
               "   uniq hangs : " cRST "%-6s " bSTG bV "\n",
      DescribeTimeDelta(cur_ms, last_hang_time).c_str(), tmp.c_str());

  MSG(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
                        " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  auto& queue_cur = *case_queue[current_entry];

  tmp = DescribeInteger(current_entry);
  if constexpr ( !option::EnableKScheduler<Tag>() ) {
    if (!queue_cur.favored) tmp += '*';
  }
  tmp += fuzzuf::utils::StrPrintf(" (%0.02f%%)",
                                  ((double)current_entry * 100) / queued_paths);

  MSG(bV bSTOP "  now processing : " cRST "%-17s " bSTG bV bSTOP, tmp.c_str());

  tmp = fuzzuf::utils::StrPrintf(
      "%0.02f%% / %0.02f%%", ((double)queue_cur.bitmap_size) * 100 / MAP_SIZE,
      t_byte_ratio);

  MSG("    map density : %s%-21s " bSTG bV "\n",
      t_byte_ratio > 70
          ? cLRD
          : ((t_bytes < 200 && !setting->dumb_mode) ? cPIN : cRST),
      tmp.c_str());

  tmp = DescribeInteger(cur_skipped_paths);
  tmp += fuzzuf::utils::StrPrintf(
      " (%0.02f%%)", ((double)cur_skipped_paths * 100) / queued_paths);

  MSG(bV bSTOP " paths timed out : " cRST "%-17s " bSTG bV, tmp.c_str());

  tmp = fuzzuf::utils::StrPrintf("%0.02f bits/tuple",
                                 t_bytes ? (((double)t_bits) / t_bytes) : 0);

  MSG(bSTOP " count coverage : " cRST "%-21s " bSTG bV "\n", tmp.c_str());

  MSG(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
                        " findings in depth " bSTG bH20 bVL "\n");

  tmp = DescribeInteger(queued_favored);
  tmp += fuzzuf::utils::StrPrintf(
      " (%0.02f%%)", ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  MSG(bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP
               " favored paths : " cRST "%-22s " bSTG bV "\n",
      stage_name.c_str(), tmp.c_str());

  if (!stage_max) {
    tmp = DescribeInteger(stage_cur) + "/-";
  } else {
    tmp = DescribeInteger(stage_cur) + "/" + DescribeInteger(stage_max);
    tmp += fuzzuf::utils::StrPrintf(" (%0.02f%%)",
                                    ((double)stage_cur) * 100 / stage_max);
  }

  MSG(bV bSTOP " stage execs : " cRST "%-21s " bSTG bV bSTOP, tmp.c_str());

  tmp = DescribeInteger(queued_with_cov);
  tmp += fuzzuf::utils::StrPrintf(
      " (%0.02f%%)", ((double)queued_with_cov) * 100 / queued_paths);

  MSG("  new edges on : " cRST "%-22s " bSTG bV "\n", tmp.c_str());

  tmp = DescribeInteger(total_crashes) + " (" + DescribeInteger(unique_crashes);
  if (unique_crashes >= GetKeepUniqueCrash(*this)) tmp += '+';
  tmp += " unique)";

  if (crash_mode != feedback::PUTExitReasonType::FAULT_NONE) {
    MSG(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
                 "   new crashes : %s%-22s " bSTG bV "\n",
        DescribeInteger(total_execs).c_str(), unique_crashes ? cLRD : cRST,
        tmp.c_str());
  } else {
    MSG(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
                 " total crashes : %s%-22s " bSTG bV "\n",
        DescribeInteger(total_execs).c_str(), unique_crashes ? cLRD : cRST,
        tmp.c_str());
  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {
    tmp = DescribeFloat(avg_exec) + "/sec (";
    if (avg_exec < 20) {
      tmp += "zzzz...";
    }
    else
      tmp += "slow!";
    tmp += ')';

    MSG(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp.c_str());
  } else {
    tmp = DescribeFloat(avg_exec) + "/sec";

    MSG(bV bSTOP "  exec speed : " cRST "%-21s ", tmp.c_str());
  }

  tmp = DescribeInteger(total_tmouts) + " (" + DescribeInteger(unique_tmouts);
  if (unique_hangs >= GetKeepUniqueHang(*this)) tmp += '+';
  tmp += " unique)";

  MSG(bSTG bV bSTOP "  total tmouts : " cRST "%-22s " bSTG bV "\n",
      tmp.c_str());

  /* Aaaalmost there... hold on! */

  MSG(bVR bH cCYA bSTOP
      " fuzzing strategy yields " bSTG bH10 bH bHT bH10 bH5 bHB bH bSTOP cCYA
      " path geometry " bSTG bH5 bH2 bH bVL "\n");

  // In original AFL, the following part is unrolled, which is too long.
  // So put them into a loop as many as possible and wish compiler's
  // optimization.

  // First, define the type describing the information output in one line:
  using OnelineInfo =
      std::tuple<const char*,  // mut_name.      e.g. "bit flips", "arithmetics"
                 const char*,  // neighbor_name. e.g. "levels", "pending", "pend
                               // fav"
                 std::string,  // neighbor_val.  e.g. DI(max_depth),
                               // DI(pending_not_fuzzed), DI(pending_favored)
                 u8,           // stage1.        e.g. STAGE_FLIP8, STAGE_ARITH8
                 u8,  // stage2.        e.g. STAGE_FLIP16, STAGE_ARITH16
                 u8   // stage3.        e.g. STAGE_FLIP32, STAGE_ARITH32
                 >;

  // Next, define each lines
  OnelineInfo line_infos[] = {
      {"   bit flips", "    levels", DescribeInteger(max_depth), STAGE_FLIP1,
       STAGE_FLIP2, STAGE_FLIP4},
      {"  byte flips", "   pending", DescribeInteger(pending_not_fuzzed),
       STAGE_FLIP8, STAGE_FLIP16, STAGE_FLIP32},
      {" arithmetics", "  pend fav", DescribeInteger(pending_favored),
       STAGE_ARITH8, STAGE_ARITH16, STAGE_ARITH32},
      {"  known ints", " own finds", DescribeInteger(queued_discovered),
       STAGE_INTEREST8, STAGE_INTEREST16, STAGE_INTEREST32},
      {"  dictionary", "  imported",
       sync_id.empty() ? "n/a" : DescribeInteger(queued_imported),
       STAGE_EXTRAS_UO, STAGE_EXTRAS_UI,
       STAGE_EXTRAS_AO}};  // Havoc is difficult to put together

  tmp = "n/a, n/a, n/a";
  for (int i = 0; i < 5; i++) {
    auto [mut_name, neighbor_name, neighbor_val, stage1, stage2, stage3] =
        line_infos[i];

    if (!skip_deterministic) {
      tmp = DescribeInteger(stage_finds[stage1]) + '/' +
            DescribeInteger(stage_cycles[stage1]) +

            ", " + DescribeInteger(stage_finds[stage2]) + '/' +
            DescribeInteger(stage_cycles[stage2]) +

            ", " + DescribeInteger(stage_finds[stage3]) + '/' +
            DescribeInteger(stage_cycles[stage3]);
    }

    MSG(bV bSTOP "%s : " cRST "%-37s " bSTG bV bSTOP "%s : " cRST
                 "%-10s " bSTG bV "\n",
        mut_name, tmp.c_str(), neighbor_name, neighbor_val.c_str());
  }

  tmp = DescribeInteger(stage_finds[STAGE_HAVOC]) + '/' +
        DescribeInteger(stage_cycles[STAGE_HAVOC]) +

        ", " + DescribeInteger(stage_finds[STAGE_SPLICE]) + '/' +
        DescribeInteger(stage_cycles[STAGE_SPLICE]);

  MSG(bV bSTOP "       havoc : " cRST "%-37s " bSTG bV bSTOP, tmp.c_str());

  if (t_bytes)
    tmp = fuzzuf::utils::StrPrintf("%0.02f%%", stab_ratio);
  else
    tmp = "n/a";

  MSG(" stability : %s%-10s " bSTG bV "\n",
      (stab_ratio < 85 && var_byte_count > 40)
          ? cLRD
          : ((queued_variable && (!persistent_mode || var_byte_count > 20))
                 ? cMGN
                 : cRST),
      tmp.c_str());

  if (!bytes_trim_out) {
    tmp = "n/a, ";
  } else {
    tmp = fuzzuf::utils::StrPrintf(
        "%0.02f%%",
        ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in);
    tmp += "/" + DescribeInteger(trim_execs) + ", ";
  }

  if (!blocks_eff_total) {
    tmp += "n/a";
  } else {
    tmp += fuzzuf::utils::StrPrintf(
        "%0.02f%%", ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
                        blocks_eff_total);
  }

  MSG(bV bSTOP "        trim : " cRST "%-37s " bSTG bVR bH20 bH2 bH2 bRB
               "\n" bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1,
      tmp.c_str());

  /* Provide some CPU utilization stats. */

  if (cpu_core_count) {
    double cur_runnable = GetRunnableProcesses(*this);
    u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

    std::string cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (cpu_aff >= 0) {
      MSG(SP10 cGRA "[cpu%03d:%s%3u%%" cGRA "]\r" cRST, std::min(cpu_aff, 999),
          cpu_color.c_str(), std::min(cur_utilization, 999u));
    } else {
      MSG(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, cpu_color.c_str(),
          std::min(cur_utilization, 999u));
    }

#else

    MSG(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, cpu_color.c_str(),
        std::min(cur_utilization, 999u));

#endif /* ^HAVE_AFFINITY */

  } else
    MSG("\r");

  /* Hallelujah! */

  fflush(0);
}

template <class Testcase>
void AFLStateTemplate<Testcase>::ReceiveStopSignal(void) {
  stop_soon = 1;
  executor->ReceiveStopSignal();
}

template <class Testcase>
bool AFLStateTemplate<Testcase>::ShouldConstructAutoDict(void) {
  return should_construct_auto_dict;
}

template <class Testcase>
void AFLStateTemplate<Testcase>::SetShouldConstructAutoDict(bool v) {
  should_construct_auto_dict = v;
}

template <class Testcase>
void AFLStateTemplate<Testcase>::LoadCentralityFile() {
  if constexpr ( !option::EnableKScheduler<Tag>() ) {
    return;
  }
  // create signal file, write 0 for initialization
  {
    std::fstream fp( "signal", std::ios::out );
    if( !fp.good() ){
      std::perror("signal open failed \n");
      std::exit(0);
    }
    fp << "0\n";
  }

  // read katz centrality
  try {
    int line_cnt = 0;
    std::fill( katz_weight.begin(), katz_weight.end(), 0 );
    const auto katz_cent = utils::kscheduler::LoadKatzCentrality( "katz_cent" );
    for( const auto &[idx,ret]: katz_cent ) {
      katz_weight[idx] = ret;
    }
    line_cnt = katz_cent.size();
    num_edge = line_cnt + 1;
  }
  catch( ... ) {
    perror("katz_cent open failed \n");
    exit(0);
  }
  
  // read border edge pair
  try {
    int line_cnt = 0;
    std::fill( border_edge_parent.begin(), border_edge_parent.end(), 0 );
    std::fill( border_edge_child.begin(), border_edge_child.end(), 0 );
    const auto border_edges = utils::kscheduler::LoadBorderEdges( "border_edges" );
    for( const auto &[parent,child]: border_edges ) {
      border_edge_parent[line_cnt] = parent;
      border_edge_child[line_cnt] = child;
      line_cnt += 1;
    }
    num_border_edge = line_cnt;
  }
  catch( ... ) {
    perror("border_edges open failed \n");
    exit(0);
  }

  // read child_list for each node
  try {
    const auto child_node = utils::kscheduler::LoadChildNode( "child_node" );
    for( const auto &c: child_node ) {
      node_child_list[ c.first ].push_back( c.second );
    }
  }
  catch( ... ) {
    perror("child_node open failed \n");
    exit(0);
  }
  //initlize 
}

}  // namespace fuzzuf::algorithm::afl
