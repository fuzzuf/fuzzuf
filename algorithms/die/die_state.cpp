/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file die_fuzzer.cpp
 * @brief Global state for HierarFlow loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <istream>
#include <sstream>
#include <string>
#include <vector>
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/die/die_option.hpp"
#include "fuzzuf/algorithms/die/die_state.hpp"
#include "fuzzuf/algorithms/die/die_testcase.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"


namespace fuzzuf::algorithm::die {

/**
 * @fn
 * @brief Copy testcase from input to queue
 */
void DIEState::PivotInputs(void) {
  ACTF("Creating hard links for all input files...");

  u32 id = 0;
  for (const auto& testcase : case_queue) {
    auto& input = *testcase->input;
    auto& input_type = *testcase->input_type;

    std::string rsl = input.GetPath().filename().string();

    const std::string case_prefix = setting->simple_files ? "id_" : "id:";

    u32 orig_id;
    std::string nfn;
    if ( rsl.substr(0, 3) == case_prefix
         && sscanf(rsl.c_str()+3, "%06u", &orig_id) == 1
         && orig_id == id) {
      resuming_fuzz = true;
      /* We don't need to add ".js" here
         because the original file name contains the extension */
      nfn = Util::StrPrintf("%s/queue/%s",
                            setting->out_dir.c_str(), rsl.c_str());

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      u32 src_id;
      auto pos = rsl.find(':');
      if ( pos != std::string::npos
           && sscanf(rsl.c_str()+pos+1, "%06u", &src_id) == 1) {

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

        if (pos != std::string::npos) pos += 6;
        else pos = 0;

        nfn = Util::StrPrintf("%s/queue/id:%06u,orig:%s",
                              setting->out_dir.c_str(),
                              id,
                              rsl.c_str() + pos);
      } else {
        nfn = Util::StrPrintf("%s/queue/id_%06u",
                              setting->out_dir.c_str(), id);
      }
    }

    /* Pivot to the new queue entry. */

    if (!input.LinkAndRefer(nfn)) {
      /* Save JS file */
      input.CopyAndRefer(nfn);
    }

    if (!input_type.LinkAndRefer(nfn + ".t")) {
      /* Save type file */
      input_type.CopyAndRefer(nfn + ".t");
    }

    /* Make sure that the passed_det value carries over, too. */

    if (testcase->passed_det) MarkAsDetDone(*testcase);

    id++;
  }

#if 0
  if (in_place_resume) NukeResumeDir();
#endif
}

/**
 * @fn
 * @brief Add JS and Type files to queue
 * @param (fn_js) Filename of JavaScript file
 * @param (buf_js) Content of JavaScript file (or nullptr)
 * @param (len_js) Size of JavaScript file
 * @param (fn_ty) Filename of type file
 * @param (buf_ty) Content of type file (or nullptr)
 * @param (len_ty) Size of type file
 * @param (passed_det) True if deterministic run is done for this testcase
 */
std::shared_ptr<DIETestcase> DIEState::AddToQueue(
  const std::string &fn_js,     // path to js file
  const u8 *buf_js, u32 len_js, // js data
  const std::string &fn_ty,     // path to type file
  const u8 *buf_ty, u32 len_ty, // type data
  bool passed_det
) {
  auto input_js = input_set.CreateOnDisk(fn_js);
  auto input_ty = input_set.CreateOnDisk(fn_ty);
  if (buf_js && buf_ty) {
    input_js->OverwriteThenUnload(buf_js, len_js);
    input_ty->OverwriteThenUnload(buf_ty, len_ty);
  }

  std::shared_ptr<DIETestcase> testcase(
    // A testcase contains JS and Type files
    new DIETestcase(std::move(input_js), std::move(input_ty))
  );

  testcase->depth = cur_depth + 1;
  testcase->passed_det = passed_det;

  if (testcase->depth > max_depth) max_depth = testcase->depth;

  case_queue.emplace_back(testcase);

  queued_paths++;
  pending_not_fuzzed++;
  cycles_wo_finds = 0;
  last_path_time = Util::GetCurTimeMs();

  return testcase;
}

/**
 * @fn
 * @brief Preprocess input JavaScript files
 */
void DIEState::ReadTestcases(void) {
  int status;
  std::vector<std::string> cmd;

  fs::path path_input  = fs::absolute(setting->in_dir);
  fs::path path_die    = fs::absolute(setting->die_dir);
  fs::path path_typer  = path_die / "fuzz/TS/typer/typer.js";
  fs::path path_esfuzz = path_die / "fuzz/TS/esfuzz.js";

  /* Create directory for JS testcase */
  Util::CreateDir((setting->out_dir / "mutated").string());

  if (!fs::is_directory(path_input)) {
    /* Exit if input path is not a directory */
    ERROR("Invalid input path (not a directory): '%s'", path_input.c_str());
  }

  if (!fs::exists(path_typer) || !fs::exists(path_esfuzz)) {
    /* Exit if typer and fuzzer does not exist in DIE path */
    ERROR("Invalid path to DIE: '%s'", path_die.c_str());
  }

  if (!fs::exists(setting->typer_path)) {
    /* Exit if typer script does not exist */
    ERROR("Invalid path to 'typer.py': '%s'", setting->typer_path.c_str());
  }

  MSG("Pre-processing input JavaScript files...\n"
      "(This process may take a while if it's the first time.)\n");

  /* Scan input directory and call typer */
  for (const auto& entry_js: fs::recursive_directory_iterator(path_input)) {
    u32 type_size;

    /* Check extension */
    fs::path path_js = entry_js.path();
    if (path_js.extension() != ".js") {
      if (path_js.extension() != ".jsi" && path_js.extension() != ".t")
        ACTF("Testcase must have a \".js\" extension: %s\n", path_js.c_str());
      continue;
    }

    /* Check file size and type */
    u32 js_size = fs::file_size(path_js);
    fs::file_status st = fs::status(path_js);

    if (!fs::is_regular_file(st) || js_size == 0)
      continue; // Skip empty files and non-regular files

    if (js_size > option::GetMaxFile())
      EXIT("Test case '%s' is too big (%s, limit is %s)",
           path_js.c_str(),
           afl::util::DescribeMemorySize(js_size).c_str(),
           afl::util::DescribeMemorySize(afl::option::GetMaxFile<Tag>()).c_str()
      ); // File size is too big

    /* Check deterministic fuzzing */
    fs::path dfn = path_input / ".state/deterministic_done" / path_js.filename();
    bool passed_det = fs::exists(dfn);

    /* Create path to instrumented JS (jsi) */
    fs::path path_jsi = path_js;
    path_jsi.replace_extension(".jsi");

    /* We don't replace extension for type file
       so that esfuzz can find this file */
    fs::path path_type = path_js.string() + ".t";

    if (fs::exists(path_type)) {
      /* Add to queue and skip if we already have type file */
      type_size = fs::file_size(path_type);
      AddToQueue(
        path_js.string(), nullptr, js_size,
        path_type.string(), nullptr, type_size,
        passed_det
      );

      ACTF("Type file exists. Skipping '%s'...", path_js.c_str());
      continue;
    }

    /* Instrument JS file */
    ACTF("Instrumenting '%s'...", path_js.c_str());

    cmd = {setting->cmd_node,   // node
           path_typer.string(), // typer.js
           path_js.string(),    // js file
           path_jsi.string()};  // instrumented js file
    status = Util::ExecuteCommand(cmd);

    if (status != 0) {
      /* Skip if instrumentation failed */
      ACTF("Instrumentation failed :(");
      continue;
    }

    /* Collect type information */
    ACTF("Profiling '%s'...", path_js.c_str());

    // Call typer.py
    cmd.clear();
    cmd = {setting->cmd_py,     // python3
           setting->typer_path, // typer.py
           setting->d8_path,    // path to d8 binary
           setting->d8_flags,   // flags for d8
           path_jsi.string(),   // instrumented js
           path_type.string()}; // path of output type file
    status = Util::ExecuteCommand(cmd);

    if (status != 0 || !fs::exists(path_type)) {
      /* Skip if profiling failed */
      ACTF("Profiling failed :(");
      continue;
    }

    /* Add testcase to queue */
    type_size = fs::file_size(path_type);
    AddToQueue(
      path_js.string(), nullptr, js_size,
      path_type.string(), nullptr, type_size,
      passed_det
    );
  }

  if (!queued_paths) {
    MSG("\n" cLRD "[-] " cRST
        "Looks like there are no valid test cases in the input directory! The fuzzer\n"
        "    needs one or more test case to start with. The cases must be stored as\n"
        "    regular files directly in the input directory.\n");

    EXIT("No usable test cases in '%s'", path_input.c_str());
  }

  /* Give some time to read the messages */
  sleep(3);

  last_path_time = 0;
  queued_at_start = queued_paths;
}

/**
 * @fn
 * @brief Save interesting testcase with type file
 * @param (buf_js) Content of JavaScript testcase
 * @param (len_js) Size of JavaScript testcase
 * @param (buf_ty) Content of type file
 * @param (len_ty) Size of type file
 * @param (inp_feed) Inplace memory feedback
 * @param (exit_status) Exit status feedback
 */
bool DIEState::SaveIfInteresting(
  const u8 *buf_js, u32 len_js,
  const u8 *buf_ty, u32 len_ty,
  InplaceMemoryFeedback &inp_feed,
  ExitStatusFeedback &exit_status
) {
  bool keeping = false;

  std::string fn;
  if (exit_status.exit_reason == crash_mode) {
    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    u8 hnb;

    inp_feed.ShowMemoryToFunc(
      [this, &hnb](const u8* trace_bits, u32 /* map_size */) {
        hnb = HasNewBits(trace_bits, &virgin_bits[0], afl::option::GetMapSize<Tag>());
      }
    );

    if (!hnb) {
      if (crash_mode == PUTExitReasonType::FAULT_CRASH) {
        total_crashes++;
      }
      return false;
    }

    if (!setting->simple_files) {
      fn = Util::StrPrintf("%s/queue/id:%06u,%s.js",
                           setting->out_dir.c_str(),
                           queued_paths,
                           afl::routine::update::DescribeOp(*this, hnb).c_str()
      );
    } else {
      fn = Util::StrPrintf("%s/queue/id_%06u.js",
                           setting->out_dir.c_str(),
                           queued_paths
      );
    }

    auto testcase = AddToQueue(
      fn, buf_js, len_js,
      fn + ".t", buf_ty, len_ty, // type file
      false
    );
    if (hnb == 2) {
      testcase->has_new_cov = 1;
      queued_with_cov++;
    }

    testcase->exec_cksum = inp_feed.CalcCksum32();

    /* FIXME: We should use refined coverage instead */
    // inp_feed will maybe discard to start a new execution
    // in that case inp_feed will receive the new feedback
    PUTExitReasonType res = CalibrateCaseWithFeedDestroyed(
      *testcase,
      buf_js, len_js,
      inp_feed,
      exit_status,
      queue_cycle - 1,
      false);

    if (res == PUTExitReasonType::FAULT_ERROR) {
      ERROR("Unable to execute target application");
    }

    keeping = true;
  }

  switch (exit_status.exit_reason) {
    case PUTExitReasonType::FAULT_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      total_tmouts++;
      if (unique_hangs >= afl::option::GetKeepUniqueHang(*this)) {
        // originally here "return keeping" is used, but this is clearer right?
        return false;
      }

      if (!setting->dumb_mode) {
          if constexpr (sizeof(size_t) == 8) {
              inp_feed.ModifyMemoryWithFunc(
                  [](u8* trace_bits, u32 /* map_size */) {
                      afl::util::SimplifyTrace<u64>((u64*)trace_bits, afl::option::GetMapSize<Tag>());
                  }
                );
          } else {
              inp_feed.ModifyMemoryWithFunc(
                  [](u8* trace_bits, u32 /* map_size */) {
                      afl::util::SimplifyTrace<u32>((u32*)trace_bits, afl::option::GetMapSize<Tag>());
                  }
              );
          }

          u8 res;
          inp_feed.ShowMemoryToFunc(
              [this, &res](const u8* trace_bits, u32 /* map_size */) {
                  res = HasNewBits(trace_bits, &virgin_tmout[0], afl::option::GetMapSize<Tag>());
              }
          );

          if (!res) {
              // originally here "return keeping" is used, but this is clearer right?
              return false;
          }
      }

      unique_tmouts++;

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (setting->exec_timelimit_ms < hang_tmout) {
        // discard inp_feed here because we will use executor
        InplaceMemoryFeedback::DiscardActive(std::move(inp_feed));
        inp_feed = RunExecutorWithClassifyCounts(
          buf_js, len_js, exit_status, hang_tmout);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!stop_soon && exit_status.exit_reason == PUTExitReasonType::FAULT_CRASH) {
          goto keep_as_crash; // FIXME: goto
        }

        if ( stop_soon
             || exit_status.exit_reason != PUTExitReasonType::FAULT_TMOUT) {
          return false;
        }
      }

      if (!setting->simple_files) {
        fn = Util::StrPrintf("%s/hangs/id:%06llu,%s.js",
                             setting->out_dir.c_str(),
                             unique_hangs,
                             afl::routine::update::DescribeOp(*this, 0).c_str()
        );
      } else {
        fn = Util::StrPrintf("%s/hangs/id_%06llu.js",
                             setting->out_dir.c_str(),
                             unique_hangs
        );
      }

      unique_hangs++;
      last_hang_time = Util::GetCurTimeMs();
      break;

    case PUTExitReasonType::FAULT_CRASH:
      keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      total_crashes++;

      if (unique_crashes >= afl::option::GetKeepUniqueCrash(*this)) {
        // unlike FAULT_TMOUT case, keeping can be true when "crash mode" is enabled
        return keeping;
      }

      if (!setting->dumb_mode) {
        if constexpr (sizeof(size_t) == 8) {
            inp_feed.ModifyMemoryWithFunc(
              [](u8* trace_bits, u32 /* map_size */) {
                afl::util::SimplifyTrace<u64>((u64*)trace_bits, afl::option::GetMapSize<Tag>());
              }
            );
          } else {
          inp_feed.ModifyMemoryWithFunc(
            [](u8* trace_bits, u32 /* map_size */) {
              afl::util::SimplifyTrace<u32>((u32*)trace_bits, afl::option::GetMapSize<Tag>());
            }
          );
        }

        u8 res;
        inp_feed.ShowMemoryToFunc(
          [this, &res](const u8* trace_bits, u32 /* map_size */) {
            res = HasNewBits(trace_bits, &virgin_crash[0], afl::option::GetMapSize<Tag>());
          }
        );

        if (!res) {
          // unlike FAULT_TMOUT case, keeping can be true when "crash mode" is enabled
          return keeping;
        }
      }

#if 0
      if (!unique_crashes) WriteCrashReadme(); // FIXME?
#endif

      if (!setting->simple_files) {
        fn = Util::StrPrintf("%s/crashes/id:%06llu,sig:%02u,%s.js",
                             setting->out_dir.c_str(),
                             unique_crashes,
                             exit_status.signal,
                             afl::routine::update::DescribeOp(*this, 0).c_str()
        );
      } else {
        fn = Util::StrPrintf("%s/hangs/id_%06llu_%02u.js",
                             setting->out_dir.c_str(),
                             unique_crashes,
                             exit_status.signal
        );
      }

      unique_crashes++;

      last_crash_time = Util::GetCurTimeMs();
      last_crash_execs = total_execs;

      break;

    case PUTExitReasonType::FAULT_ERROR:
      ERROR("Unable to execute target application");

    default:
      return keeping;
  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */
  int fd;

  fd = Util::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  Util::WriteFile(fd, buf_js, len_js);
  Util::CloseFile(fd);

  // Save type file
  fd = Util::OpenFile(fn + ".t", O_WRONLY | O_CREAT | O_EXCL, 0600);
  Util::WriteFile(fd, buf_ty, len_ty);
  Util::CloseFile(fd);

  return keeping;
}

/**
 * @fn
 * @brief Show status of DIE fuzzer
 */
void DIEState::ShowStats(void) {
  // Lots of constants appear, so overlook this.
  using namespace afl::option;

  const u32 MAP_SIZE = GetMapSize<Tag>();

  u64 cur_ms = Util::GetCurTimeMs();

  /* If not enough time has passed since last UI update, bail out. */
  if (cur_ms - last_ms < 1000 / GetUiTargetHz(*this)) return;

  /* Check if we're past the 10 minute mark. */
  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = true;

  /* Calculate smoothed exec speed stats. */
  if (last_execs == 0) {
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);
  } else {
    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
      (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */
    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / GetAvgSmoothing(*this)) +
      cur_avg  *       (1.0 / GetAvgSmoothing(*this));
  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */
  stats_update_freq = avg_exec / (GetUiTargetHz(*this) * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* Do some bitmap stats. */
  u32 t_bytes = Util::CountNon255Bytes(&virgin_bits[0], virgin_bits.size());
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
    MaybeUpdatePlotFile(t_byte_ratio, avg_exec);
  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */
  if (!setting->dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE")) stop_soon = 2;

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH")) stop_soon = 2;

  /* If we're not on TTY, bail out. */
  if (not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */
  u32 t_bits = (MAP_SIZE << 3) - Util::CountBits(&virgin_bits[0], virgin_bits.size());

  /* Now, for the visuals... */
  bool term_too_small = false;
  if (clear_screen) {
    MSG(TERM_CLEAR CURSOR_HIDE);
    clear_screen = false;

    term_too_small = afl::CheckTermSize();
  }

  MSG(TERM_HOME);

  if (term_too_small) {
    MSG(cBRI "Your terminal is too small to display the UI.\n"
        "Please resize terminal window to at least 80x25.\n" cRST);

    return;
  }

  // FIXME: use stringstream...?
  // anyways it's weird to mix up sprintf and std::string

  /* Let's start by drawing a centered banner. */
  u32 banner_len = (crash_mode != PUTExitReasonType::FAULT_NONE ? 24 : 22)
    + strlen(GetVersion(*this)) + use_banner.size();
  u32 banner_pad = (80 - banner_len) / 2;

  auto fuzzer_name = crash_mode != PUTExitReasonType::FAULT_NONE
    ? cPIN "fuzzuf peruvian were-rabbit"
    : cYEL "fuzzuf american fuzzy lop";

  std::string tmp(banner_pad, ' ');
  tmp += Util::StrPrintf("%s " cLCY "%s" cLGN " (%s)",
                         fuzzer_name, GetVersion(*this), use_banner.c_str());
  MSG("\n%s\n\n", tmp.c_str());

  /* Lord, forgive me this. */
  MSG(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
      bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

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
    } else if (cycles_wo_finds > 100
               && !pending_not_fuzzed && min_wo_finds > 120) {
      /* No finds for a long time and no test cases to try. */
      col = cLGN;
    } else {
      /* Default: cautiously OK to stop? */
      col = cLBL;
    }
  }

  // From here, we use these a lot...!
  using afl::util::DescribeInteger;
  using afl::util::DescribeFloat;
  using afl::util::DescribeTimeDelta;

  MSG(bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
      " current seed : " cRST "%-5s  " bSTG bV "\n",
      DescribeTimeDelta(cur_ms, start_time).c_str(),
      DescribeInteger(current_entry).c_str());

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!setting->dumb_mode &&
      ( last_path_time
        || resuming_fuzz
        || queue_cycle == 1
        || !in_bitmap.empty()
        || crash_mode != PUTExitReasonType::FAULT_NONE)
  ) {

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
  if (!queue_cur.favored) tmp += '*';
  tmp += Util::StrPrintf(" (%0.02f%%)", ((double)current_entry * 100) / queued_paths);

  MSG(bV bSTOP "  now processing : " cRST "%-17s " bSTG bV bSTOP, tmp.c_str());

  tmp = Util::StrPrintf("%0.02f%% / %0.02f%%",
                        ((double)queue_cur.bitmap_size) * 100 / MAP_SIZE, t_byte_ratio);

  MSG("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD :
      ((t_bytes < 200 && !setting->dumb_mode) ? cPIN : cRST), tmp.c_str());

  tmp = DescribeInteger(cur_skipped_paths);
  tmp += Util::StrPrintf(" (%0.02f%%)", ((double)cur_skipped_paths * 100) / queued_paths);

  MSG(bV bSTOP " paths timed out : " cRST "%-17s " bSTG bV, tmp.c_str());

  tmp = Util::StrPrintf("%0.02f bits/tuple", t_bytes ? (((double)t_bits) / t_bytes) : 0);

  MSG(bSTOP " count coverage : " cRST "%-21s " bSTG bV "\n", tmp.c_str());

  MSG(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
      " findings in depth " bSTG bH20 bVL "\n");

  tmp = DescribeInteger(queued_favored);
  tmp += Util::StrPrintf(" (%0.02f%%)", ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  MSG(bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP
      " favored paths : " cRST "%-22s " bSTG bV "\n", stage_name.c_str(), tmp.c_str());

  if (!stage_max) {
    tmp = DescribeInteger(stage_cur) + "/-";
  } else {
    tmp = DescribeInteger(stage_cur) + "/" + DescribeInteger(stage_max);
    tmp += Util::StrPrintf(" (%0.02f%%)", ((double)stage_cur) * 100 / stage_max);
  }

  MSG(bV bSTOP " stage execs : " cRST "%-21s " bSTG bV bSTOP, tmp.c_str());

  tmp = DescribeInteger(queued_with_cov);
  tmp += Util::StrPrintf(" (%0.02f%%)", ((double)queued_with_cov) * 100 / queued_paths);

  MSG("  new edges on : " cRST "%-22s " bSTG bV "\n", tmp.c_str());

  tmp = DescribeInteger(total_crashes) + " ("
    + DescribeInteger(unique_crashes);
  if (unique_crashes >= GetKeepUniqueCrash(*this)) tmp += '+';
  tmp += " unique)";

  if (crash_mode != PUTExitReasonType::FAULT_NONE) {
    MSG(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
        "   new crashes : %s%-22s " bSTG bV "\n",
        DescribeInteger(total_execs).c_str(),
        unique_crashes ? cLRD : cRST, tmp.c_str());
  } else {
    MSG(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
        " total crashes : %s%-22s " bSTG bV "\n",
        DescribeInteger(total_execs).c_str(),
        unique_crashes ? cLRD : cRST, tmp.c_str());
  }

  /* Show a warning about slow execution. */

  if (avg_exec < 20) { // JS mutation is relatively slow!
    tmp = DescribeFloat(avg_exec) + "/sec (";
    if (avg_exec < 10) tmp += "zzzz...";
    else tmp += "slow!";
    tmp += ')';

    MSG(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp.c_str());
  } else {
    tmp = DescribeFloat(avg_exec) + "/sec";

    MSG(bV bSTOP "  exec speed : " cRST "%-21s ", tmp.c_str());
  }

  tmp = DescribeInteger(total_tmouts) + " (" +
    DescribeInteger(unique_tmouts);
  if (unique_hangs >= GetKeepUniqueHang(*this)) tmp += '+';
  tmp += ')';

  MSG (bSTG bV bSTOP "  total tmouts : " cRST "%-22s " bSTG bV "\n", tmp.c_str());

  /* We don't show fuzzing strategy. Who flips bits in JavaScript? */

  MSG(bLB bH30 bH5 bH2 bHT bH30 bH10 bRB bSTOP cRST RESET_G1"\n");

  /* Provide some CPU utilization stats. */

  if (executor->cpu_core_count) {
    double cur_runnable = GetRunnableProcesses(*this);
    u32 cur_utilization = cur_runnable * 100 / executor->cpu_core_count;

    std::string cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (executor->cpu_core_count > 1 &&
        cur_runnable + 1 <= executor->cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (executor->binded_cpuid.has_value()) {
      MSG(SP20 SP20 SP20 SP5 cGRA "[cpu%03d:%s%3u%%" cGRA "]\r" cRST,
          std::min(executor->binded_cpuid.value(), 999),
          cpu_color.c_str(), std::min(cur_utilization, 999u));
    } else {
      MSG(SP20 SP20 SP20 SP5 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
          cpu_color.c_str(), std::min(cur_utilization, 999u));
    }

#else

    MSG(SP20 SP20 SP20 SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
        cpu_color.c_str(), std::min(cur_utilization, 999u));

#endif /* ^HAVE_AFFINITY */

  } else MSG("\r");

  /* Hallelujah! */

  fflush(0);
}


} // namespace fuzzuf::algorithm::die
