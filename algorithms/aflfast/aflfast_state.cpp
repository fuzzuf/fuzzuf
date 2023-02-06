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
#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"

#include "fuzzuf/algorithms/afl/afl_macro.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_option.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::aflfast {

// FIXME: check if we are initializing all the members that need to be
// initialized
AFLFastState::AFLFastState(
    std::shared_ptr<const AFLFastSetting> setting,
    std::shared_ptr<executor::AFLExecutorInterface> executor,
    std::unique_ptr<optimizer::HavocOptimizer> &&havoc_optimizer)
    : AFLStateTemplate<AFLFastTestcase>(setting, executor,
                                        std::move(havoc_optimizer)),
      setting(setting) {}

std::shared_ptr<AFLFastTestcase> AFLFastState::AddToQueue(const std::string &fn,
                                                          const u8 *buf,
                                                          u32 len,
                                                          bool passed_det) {
  std::shared_ptr<AFLFastTestcase> testcase =
      AFLStateTemplate<AFLFastTestcase>::AddToQueue(fn, buf, len, passed_det);
  testcase->n_fuzz = 1;

  return testcase;
}

void AFLFastState::UpdateBitmapScoreWithRawTrace(AFLFastTestcase &testcase,
                                                 const u8 *trace_bits,
                                                 u32 map_size) {
  u64 fuzz_p2 = fuzzuf::utils::NextP2(testcase.n_fuzz);
  u64 fav_factor = testcase.exec_us * testcase.input->GetLen();

  for (u32 i = 0; i < map_size; i++) {
    if (trace_bits[i]) {
      if (top_rated[i]) {
        auto &top_testcase = top_rated[i].value().get();

        u64 top_rated_fuzz_p2 = fuzzuf::utils::NextP2(top_testcase.n_fuzz);
        u64 factor = top_testcase.exec_us * top_testcase.input->GetLen();

        if (fuzz_p2 > top_rated_fuzz_p2)
          continue;
        else if (fuzz_p2 == top_rated_fuzz_p2) {
          if (fav_factor > factor) continue;
        }

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
        testcase.trace_mini.reset(
            new std::bitset<afl::option::GetMapSize<Tag>()>());

        auto &trace_mini = *testcase.trace_mini;
        for (u32 j = 0; j < afl::option::GetMapSize<Tag>(); j++) {
          trace_mini[j] = trace_bits[j] != 0;
        }
      }

      score_changed = true;
    }
  }
}

bool AFLFastState::SaveIfInteresting(
    const u8 *buf, u32 len, feedback::InplaceMemoryFeedback &inp_feed,
    feedback::ExitStatusFeedback &exit_status) {
  /* Update path frequency. */
  u32 cksum = inp_feed.CalcCksum32();
  for (auto &testcase : case_queue) {
    if (testcase->exec_cksum == cksum) {
      testcase->n_fuzz += 1;
    }
  }

  return AFLStateTemplate<AFLFastTestcase>::SaveIfInteresting(
      buf, len, inp_feed, exit_status);
}

u32 AFLFastState::DoCalcScore(AFLFastTestcase &testcase) {
  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

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

  u64 fuzz = testcase.n_fuzz;
  u64 fuzz_total;

  u32 n_paths, fuzz_mu;
  u32 factor = 1;

  switch (setting->schedule) {
    case option::EXPLORE:
      break;

    case option::EXPLOIT:
      factor = option::GetMaxFactor(*this);
      break;

    case option::COE:
      fuzz_total = 0;
      n_paths = 0;

      for (const auto &testcase : case_queue) {
        fuzz_total += testcase->n_fuzz;
        n_paths++;
      }

      fuzz_mu = fuzz_total / n_paths;
      if (fuzz <= fuzz_mu) {
        if (testcase.fuzz_level < 16) {
          factor = ((u32)(1 << testcase.fuzz_level));
        } else {
          factor = option::GetMaxFactor(*this);
        }
      } else {
        factor = 0;
      }
      break;

    case option::FAST:
      if (testcase.fuzz_level < 16) {
        factor = ((u32)(1 << testcase.fuzz_level)) / (fuzz == 0 ? 1 : fuzz);
      } else {
        factor = option::GetMaxFactor(*this) /
                 (fuzz == 0 ? 1 : fuzzuf::utils::NextP2(fuzz));
      }
      break;

    case option::LIN:
      factor = testcase.fuzz_level / (fuzz == 0 ? 1 : fuzz);
      break;

    case option::QUAD:
      factor =
          testcase.fuzz_level * testcase.fuzz_level / (fuzz == 0 ? 1 : fuzz);
      break;

    default:
      ERROR("Unknown Power Schedule");
  }

  if (factor > option::GetMaxFactor(*this)) {
    factor = option::GetMaxFactor(*this);
  }

  perf_score *= factor / option::GetPowerBeta(*this);

  /* Make sure that we don't go over limit. */

  if (perf_score > afl::option::GetHavocMaxMult(*this) * 100) {
    perf_score = afl::option::GetHavocMaxMult(*this) * 100;
  }

  return perf_score;
}

void AFLFastState::ShowStats(void) {
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
  u32 t_bytes =
      fuzzuf::utils::CountNon255Bytes(&virgin_bits[0], virgin_bits.size());
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
  if (cur_ms - last_plot_ms > GetPlotUpdateSec(*this) * 1000) {
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
  u32 t_bits = (MAP_SIZE << 3) -
               fuzzuf::utils::CountBits(&virgin_bits[0], virgin_bits.size());

  /* Now, for the visuals... */
  bool term_too_small = false;
  if (clear_screen) {
    MSG(TERM_CLEAR);
    clear_screen = false;

    term_too_small = afl::CheckTermSize();
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
                         : cYEL "fuzzuf american fuzzy lop (fast)";

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

  auto &queue_cur = *case_queue[current_entry];

  tmp = DescribeInteger(current_entry);
  tmp += queue_cur.favored ? "." : "*";
  tmp += fuzzuf::utils::StrPrintf("%d", queue_cur.fuzz_level);
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
    if (avg_exec < 20)
      tmp += "zzzz...";
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
  using OnelineInfo = std::tuple<
      const char *,  // mut_name.      e.g. "bit flips", "arithmetics"
      const char *,  // neighbor_name. e.g. "levels", "pending", "pend fav"
      std::string,   // neighbor_val.  e.g. DI(max_depth),
                     // DI(pending_not_fuzzed), DI(pending_favored)
      u8,            // stage1.        e.g. STAGE_FLIP8, STAGE_ARITH8
      u8,            // stage2.        e.g. STAGE_FLIP16, STAGE_ARITH16
      u8             // stage3.        e.g. STAGE_FLIP32, STAGE_ARITH32
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

}  // namespace fuzzuf::algorithm::aflfast
