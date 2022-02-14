/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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

#include <sys/ioctl.h>
#include <vector>
#include <string>
#include <memory>

#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_setting.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/algorithms/afl/afl_macro.hpp"
#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp"

namespace fuzzuf::algorithm::afl {

// FIXME: check if we are initializing all the members that need to be initialized
template<class Testcase>
AFLStateTemplate<Testcase>::AFLStateTemplate(
    std::shared_ptr<const AFLSetting> setting,
    std::shared_ptr<NativeLinuxExecutor> executor
)
    : setting( setting ),
      executor( executor ),
      input_set(),
      rand_fd( Util::OpenFile("/dev/urandom", O_RDONLY | O_CLOEXEC) ),
      should_construct_auto_dict(false)
{
    if (in_bitmap.empty()) virgin_bits.assign(option::GetMapSize<Tag>(), 255);
    else {
        ReadBitmap(in_bitmap);
    }

    /* Gnuplot output file. */

    auto plot_fn = setting->out_dir / "plot_data";
    plot_file = fopen(plot_fn.c_str(), "w");
    if (!plot_file) ERROR("Unable to create '%s'", plot_fn.c_str());

    fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                       "pending_total, pending_favs, map_size, unique_crashes, "
                       "unique_hangs, max_depth, execs_per_sec\n");
}

template<class Testcase>
AFLStateTemplate<Testcase>::~AFLStateTemplate() {
    if (rand_fd != -1) {
        Util::CloseFile(rand_fd);
        rand_fd = -1;
    }

    fclose(plot_file);
}

template<class Testcase>
InplaceMemoryFeedback AFLStateTemplate<Testcase>::RunExecutorWithClassifyCounts(
    const u8* buf,
    u32 len,
    ExitStatusFeedback &exit_status,
    u32 tmout
) {
    total_execs++;

    if (tmout == 0) {
        executor->Run(buf, len);
    } else {
        executor->Run(buf, len, tmout);
    }

    auto inp_feed = executor->GetAFLFeedback();
    exit_status = executor->GetExitStatusFeedback();

    if constexpr (sizeof(size_t) == 8) {
        inp_feed.ModifyMemoryWithFunc(
            [](u8* trace_bits, u32 /* map_size */) {
                afl::util::ClassifyCounts<u64>((u64*)trace_bits, option::GetMapSize<Tag>());
            }
        );
    } else {
        inp_feed.ModifyMemoryWithFunc(
            [](u8* trace_bits, u32 /* map_size */) {
                afl::util::ClassifyCounts<u32>((u32*)trace_bits, option::GetMapSize<Tag>());
            }
        );
    }

    return InplaceMemoryFeedback(std::move(inp_feed));
}

template<class Testcase>
PUTExitReasonType AFLStateTemplate<Testcase>::CalibrateCaseWithFeedDestroyed(
    Testcase &testcase,
    const u8 *buf,
    u32 len,
    InplaceMemoryFeedback &inp_feed,
    ExitStatusFeedback &exit_status,
    u32 handicap,
    bool from_queue
) {
    std::array<u8, option::GetMapSize<Tag>()> first_trace;

    bool first_run = testcase.exec_cksum == 0;

    s32 old_sc = stage_cur;
    s32 old_sm = stage_max;
    std::string old_sn = std::move(stage_name);

    u32 use_tmout;
    if (!from_queue || resuming_fuzz) {
        use_tmout = std::max(setting->exec_timelimit_ms + option::GetCalTmoutAdd(*this),
                             setting->exec_timelimit_ms * option::GetCalTmoutPerc(*this) / 100);
    } else {
        use_tmout = setting->exec_timelimit_ms;
    }

    testcase.cal_failed++;

    stage_name = "calibration";
    stage_max = fast_cal ? 3 : option::GetCalCycles(*this);

    u8 hnb = 0;
    u8 new_bits = 0;
    if (testcase.exec_cksum) {
        inp_feed.ShowMemoryToFunc(
            [this, &first_trace, &hnb](const u8* trace_bits, u32 /* map_size */) {
                std::memcpy(first_trace.data(), trace_bits, option::GetMapSize<Tag>());
                hnb = HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
            }
        );

        if (hnb > new_bits) new_bits = hnb;
    }

    bool var_detected = false;
    u64 start_us = Util::GetCurTimeUs();
    u64 stop_us;
    for (stage_cur=0; stage_cur < stage_max; stage_cur++) {

        if (!first_run && stage_cur % stats_update_freq == 0) {
            ShowStats();
        }

        InplaceMemoryFeedback::DiscardActive(std::move(inp_feed));
        inp_feed =
            RunExecutorWithClassifyCounts(buf, len, exit_status, use_tmout);

        /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
           we want to bail out quickly. */

        if (stop_soon || exit_status.exit_reason != crash_mode)
            goto abort_calibration; // FIXME: goto

        if (!setting->dumb_mode && !stage_cur && !inp_feed.CountNonZeroBytes()) {
            exit_status.exit_reason = PUTExitReasonType::FAULT_NOINST;
            goto abort_calibration; // FIXME: goto
        }

        u32 cksum = inp_feed.CalcCksum32();

        if (testcase.exec_cksum != cksum) {
            inp_feed.ShowMemoryToFunc(
                [this, &hnb](const u8* trace_bits, u32 /* map_size */) {
                    hnb = HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
                }
            );

            if (hnb > new_bits) new_bits = hnb;

            if (testcase.exec_cksum) {
                inp_feed.ShowMemoryToFunc(
                    [this, &first_trace](const u8* trace_bits, u32 /* map_size */) {
                        for (u32 i=0; i < option::GetMapSize<Tag>(); i++) {
                            if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {
                                var_bytes[i] = 1;
                                stage_max = option::GetCalCyclesLong(*this);
                            }
                        }
                    }
                );

                var_detected = true;
            } else {
                testcase.exec_cksum = cksum;
                inp_feed.ShowMemoryToFunc(
                    [&first_trace](const u8* trace_bits, u32 /* map_size */) {
                        std::memcpy(first_trace.data(), trace_bits, option::GetMapSize<Tag>());
                    }
                );
            }
        }
    }

    stop_us = Util::GetCurTimeUs();

    total_cal_us += stop_us - start_us;
    total_cal_cycles += stage_max;

    testcase.exec_us = (stop_us - start_us) / stage_max;
    testcase.bitmap_size = inp_feed.CountNonZeroBytes();
    testcase.handicap = handicap;
    testcase.cal_failed = 0;

    total_bitmap_size += testcase.bitmap_size;
    total_bitmap_entries++;

    UpdateBitmapScore(testcase, inp_feed);

    /* If this case didn't result in new output from the instrumentation, tell
       parent. This is a non-critical problem, but something to warn the user
       about. */

    if ( !setting->dumb_mode
      && first_run
      && exit_status.exit_reason == PUTExitReasonType::FAULT_NONE
      && new_bits == 0) {
        exit_status.exit_reason = PUTExitReasonType::FAULT_NOBITS;
    }

abort_calibration:

    if (new_bits == 2 && !testcase.has_new_cov) {
        testcase.has_new_cov = true;
        queued_with_cov++;
    }

    /* Mark variable paths. */

    if (var_detected) {
        var_byte_count = Util::CountBytes(&var_bytes[0], var_bytes.size());
        if (!testcase.var_behavior) {
            MarkAsVariable(testcase);
            queued_variable++;
        }
    }

    stage_name = old_sn;
    stage_cur  = old_sc;
    stage_max  = old_sm;

    if (!first_run) ShowStats();

    return exit_status.exit_reason;
}

// Difference with AFL's add_to_queue:
// if buf is not nullptr, then this function saves "buf" in a file specified by "fn"

template<class Testcase>
std::shared_ptr<Testcase> AFLStateTemplate<Testcase>::AddToQueue(
    const std::string &fn,
    const u8 *buf,
    u32 len,
    bool passed_det
) {
    auto input = input_set.CreateOnDisk(fn);
    if (buf) {
        input->OverwriteThenUnload(buf, len);
    }

    std::shared_ptr<Testcase> testcase( new Testcase(std::move(input)) );

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

template<class Testcase>
void AFLStateTemplate<Testcase>::UpdateBitmapScoreWithRawTrace(
    Testcase &testcase,
    const u8 *trace_bits,
    u32 map_size
) {
    u64 fav_factor = testcase.exec_us * testcase.input->GetLen();

    for (u32 i=0; i<map_size; i++) {
        if (trace_bits[i]) {
            if (top_rated[i]) {
                auto &top_testcase = top_rated[i].value().get();
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
                testcase.trace_mini.reset(
                    new std::bitset<option::GetMapSize<Tag>()>()
                );

                auto& trace_mini = *testcase.trace_mini;
                for (u32 j=0; j < option::GetMapSize<Tag>(); j++) {
                    trace_mini[j] = trace_bits[j] != 0;
                }
            }

            score_changed = true;
        }
    }
}

template<class Testcase>
void AFLStateTemplate<Testcase>::UpdateBitmapScore(
    Testcase &testcase,
    const InplaceMemoryFeedback &inp_feed
) {
    inp_feed.ShowMemoryToFunc(
        [this, &testcase](const u8* trace_bits, u32 /* map_size */) {
            UpdateBitmapScoreWithRawTrace(testcase, trace_bits, option::GetMapSize<Tag>());
        }
    );
}


template<class Testcase>
bool AFLStateTemplate<Testcase>::SaveIfInteresting(
    const u8 *buf,
    u32 len,
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
                hnb = HasNewBits(trace_bits, &virgin_bits[0], option::GetMapSize<Tag>());
            }
        );

        if (!hnb) {
            if (crash_mode == PUTExitReasonType::FAULT_CRASH) {
                total_crashes++;
            }
            return false;
        }

        if (!setting->simple_files) {
            fn = Util::StrPrintf("%s/queue/id:%06u,%s",
                                    setting->out_dir.c_str(),
                                    queued_paths,
                                    routine::update::DescribeOp(*this, hnb).c_str()
                                );
        } else {
            fn = Util::StrPrintf("%s/queue/id_%06u",
                                    setting->out_dir.c_str(),
                                    queued_paths
                                );
        }

        auto testcase = AddToQueue(fn, buf, len, false);
        if (hnb == 2) {
            testcase->has_new_cov = 1;
            queued_with_cov++;
        }

        testcase->exec_cksum = inp_feed.CalcCksum32();

        // inp_feed will may be discard to start a new execution
        // in that case inp_feed will receive the new feedback
        PUTExitReasonType res = CalibrateCaseWithFeedDestroyed(
                  *testcase,
                  buf, len,
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
        if (unique_hangs >= option::GetKeepUniqueHang(*this)) {
            // originally here "return keeping" is used, but this is clearer right?
            return false;
        }

        if (!setting->dumb_mode) {
            if constexpr (sizeof(size_t) == 8) {
                inp_feed.ModifyMemoryWithFunc(
                    [](u8* trace_bits, u32 /* map_size */) {
                        afl::util::SimplifyTrace<u64>((u64*)trace_bits, option::GetMapSize<Tag>());
                    }
                );
            } else {
                inp_feed.ModifyMemoryWithFunc(
                    [](u8* trace_bits, u32 /* map_size */) {
                        afl::util::SimplifyTrace<u32>((u32*)trace_bits, option::GetMapSize<Tag>());
                    }
                );
            }

            u8 res;
            inp_feed.ShowMemoryToFunc(
                [this, &res](const u8* trace_bits, u32 /* map_size */) {
                    res = HasNewBits(trace_bits, &virgin_tmout[0], option::GetMapSize<Tag>());
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
                                buf, len, exit_status, hang_tmout);

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
            fn = Util::StrPrintf("%s/hangs/id:%06llu,%s",
                                    setting->out_dir.c_str(),
                                    unique_hangs,
                                    routine::update::DescribeOp(*this, 0).c_str()
                                );
        } else {
            fn = Util::StrPrintf("%s/hangs/id_%06llu",
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

        if (unique_crashes >= option::GetKeepUniqueCrash(*this)) {
            // unlike FAULT_TMOUT case, keeping can be true when "crash mode" is enabled
            return keeping;
        }

        if (!setting->dumb_mode) {
            if constexpr (sizeof(size_t) == 8) {
                inp_feed.ModifyMemoryWithFunc(
                    [](u8* trace_bits, u32 /* map_size */) {
                        afl::util::SimplifyTrace<u64>((u64*)trace_bits, option::GetMapSize<Tag>());
                    }
                );
            } else {
                inp_feed.ModifyMemoryWithFunc(
                    [](u8* trace_bits, u32 /* map_size */) {
                        afl::util::SimplifyTrace<u32>((u32*)trace_bits, option::GetMapSize<Tag>());
                    }
                );
            }

            u8 res;
            inp_feed.ShowMemoryToFunc(
                [this, &res](const u8* trace_bits, u32 /* map_size */) {
                    res = HasNewBits(trace_bits, &virgin_crash[0], option::GetMapSize<Tag>());
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
            fn = Util::StrPrintf("%s/crashes/id:%06llu,sig:%02u,%s",
                                    setting->out_dir.c_str(),
                                    unique_crashes,
                                    exit_status.signal,
                                    routine::update::DescribeOp(*this, 0).c_str()
                                );
        } else {
            fn = Util::StrPrintf("%s/hangs/id_%06llu_%02u",
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

    int fd = Util::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    Util::WriteFile(fd, buf, len);
    Util::CloseFile(fd);

    return keeping;
}

template<class Testcase>
u32 AFLStateTemplate<Testcase>::DoCalcScore(Testcase &testcase) {
    u32 avg_exec_us = total_cal_us / total_cal_cycles;
    u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
    u32 perf_score = 100;

    /* Adjust score based on execution speed of this path, compared to the
       global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
       less expensive to fuzz, so we're giving them more air time. */

    if (testcase.exec_us * 0.1 > avg_exec_us) perf_score = 10;
    else if (testcase.exec_us * 0.25 > avg_exec_us) perf_score = 25;
    else if (testcase.exec_us * 0.5 > avg_exec_us) perf_score = 50;
    else if (testcase.exec_us * 0.75 > avg_exec_us) perf_score = 75;
    else if (testcase.exec_us * 4 < avg_exec_us) perf_score = 300;
    else if (testcase.exec_us * 3 < avg_exec_us) perf_score = 200;
    else if (testcase.exec_us * 2 < avg_exec_us) perf_score = 150;

    /* Adjust score based on bitmap size. The working theory is that better
       coverage translates to better targets. Multiplier from 0.25x to 3x. */

    if (testcase.bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
    else if (testcase.bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
    else if (testcase.bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
    else if (testcase.bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
    else if (testcase.bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
    else if (testcase.bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

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

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.
   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

template<class Testcase>
u8 AFLStateTemplate<Testcase>::HasNewBits(const u8 *trace_bits, u8 *virgin_map, u32 map_size) {
    // we assume the word size is the same as sizeof(size_t)
    static_assert( sizeof(size_t) == 4 || sizeof(size_t) == 8 );
    using UInt = std::conditional_t<sizeof(size_t) == 4, u32, u64>;

    constexpr int width = sizeof(UInt);
    constexpr int wlog =   width == 4 ?  2 :
                        /* width == 8 */ 3 ;

    UInt* virgin  = (UInt*)virgin_map;
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

                for (int j=0; j < width; j++) {
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

template<class Testcase>
void AFLStateTemplate<Testcase>::MarkAsDetDone(Testcase &testcase) {
    const auto& input = *testcase.input;

    std::string fn = input.GetPath().filename().string();
    fn = Util::StrPrintf("%s/queue/.state/deterministic_done/%s",
            setting->out_dir.c_str(), fn.c_str());

    int fd = Util::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    Util::CloseFile(fd);

    testcase.passed_det = true;
}

template<class Testcase>
void AFLStateTemplate<Testcase>::MarkAsVariable(Testcase &testcase) {
    const auto& input = *testcase.input;

    std::string fn = input.GetPath().filename().string();
    std::string ldest = Util::StrPrintf("../../%s", fn.c_str());
    fn = Util::StrPrintf("%s/queue/.state/variable_behavior/%s",
            setting->out_dir.c_str(), fn.c_str());

    if (symlink(ldest.c_str(), fn.c_str()) == -1) {
        int fd = Util::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
        Util::CloseFile(fd);
    }

    testcase.var_behavior = true;
}

template<class Testcase>
void AFLStateTemplate<Testcase>::MarkAsRedundant(Testcase &testcase, bool val) {
    const auto& input = *testcase.input;

    if (val == testcase.fs_redundant) return;

    testcase.fs_redundant = val;

    std::string fn = input.GetPath().filename().string();
    fn = Util::StrPrintf("%s/queue/.state/redundant_edges/%s",
            setting->out_dir.c_str(), fn.c_str());

    if (val) {
        int fd = Util::OpenFile(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
        Util::CloseFile(fd);
    } else {
        if (unlink(fn.c_str())) ERROR("Unable to remove '%s'", fn.c_str());
    }
}

/* Get the number of runnable processes, with some simple smoothing. */

template<class State>
static double GetRunnableProcesses(State &state) {
    // FIXME: static variable
    static double res = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

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
            !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);
      }

    fclose(f);

    if (!res) {
        res = val;
    } else {
        res =     res * (1.0 - 1.0 / option::GetAvgSmoothing(state)) +
              ((double)val) * (1.0 / option::GetAvgSmoothing(state));
    }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

    return res;
}

/* Update stats file for unattended monitoring. */

template<class Testcase>
void AFLStateTemplate<Testcase>::WriteStatsFile(double bitmap_cvg, double stability, double eps) {
    auto fn = setting->out_dir / "fuzzer_stats";
    int fd = Util::OpenFile(fn.string(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) ERROR("Unable to create '%s'", fn.c_str());

    FILE* f = fdopen(fd, "w");
    if (!f) ERROR("fdopen() failed");

    /* Keep last values in case we're called from another context
       where exec/sec stats and such are not readily available. */

    if (!bitmap_cvg && !stability && !eps) {
        bitmap_cvg = last_bcvg;
        stability  = last_stab;
        eps        = last_eps;
    } else {
        last_bcvg = bitmap_cvg;
        last_stab = stability;
        last_eps  = eps;
    }

    fprintf(f, "start_time        : %llu\n"
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
               start_time / 1000, Util::GetCurTimeMs() / 1000, getpid(),
               queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
               queued_paths, queued_favored, queued_discovered, queued_imported,
               max_depth, current_entry, pending_favored, pending_not_fuzzed,
               queued_variable, stability, bitmap_cvg, unique_crashes,
               unique_hangs, last_path_time / 1000, last_crash_time / 1000,
               last_hang_time / 1000, total_execs - last_crash_execs,
               setting->exec_timelimit_ms, use_banner.c_str(), option::GetVersion(*this),
               qemu_mode ? "qemu " : "", setting->dumb_mode ? " dumb " : "",
               no_forkserver ? "no_forksrv " : "",
               crash_mode != PUTExitReasonType::FAULT_NONE ? "crash " : "",
               persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
               (qemu_mode || setting->dumb_mode || no_forkserver ||
               crash_mode != PUTExitReasonType::FAULT_NONE ||
                persistent_mode || deferred_mode) ? "" : "default",
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

template<class Testcase>
void AFLStateTemplate<Testcase>::SaveAuto(void) {
    if (!auto_changed) return;
    auto_changed = false;

    u32 lim = std::min<u32>(option::GetUseAutoExtras(*this), a_extras.size());
    for (u32 i=0; i<lim; i++) {
        auto fn =   setting->out_dir
                  / "queue/.state/auto_extras"
                  / Util::StrPrintf("auto_%06u", i);

        int fd = Util::OpenFile(fn.string(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) ERROR("Unable to create '%s'", fn.c_str());

        Util::WriteFile(fd, &a_extras[i].data[0], a_extras[i].data.size());
        Util::CloseFile(fd);
    }
}

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

template<class Testcase>
void AFLStateTemplate<Testcase>::WriteBitmap(void) {
    if (!bitmap_changed) return;
    bitmap_changed = false;

    auto fn = setting->out_dir  / "fuzz_bitmap";

    int fd = Util::OpenFile(fn.string(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) ERROR("Unable to create '%s'", fn.c_str());

    Util::WriteFile(fd, virgin_bits.data(), option::GetMapSize<Tag>());
    Util::CloseFile(fd);
}

/* Read bitmap from file. This is for the -B option again. */

template<class Testcase>
void AFLStateTemplate<Testcase>::ReadBitmap(fs::path fname) {
    int fd = Util::OpenFile(fname.string(), O_RDONLY);
    if (fd < 0) ERROR("Unable to open '%s'", fname.c_str());

    virgin_bits.resize(option::GetMapSize<Tag>());
    Util::ReadFile(fd, virgin_bits.data(), option::GetMapSize<Tag>());
    Util::CloseFile(fd);
}

template<class Testcase>
void AFLStateTemplate<Testcase>::MaybeUpdatePlotFile(double bitmap_cvg, double eps) {

    if (prev_qp == queued_paths && prev_pf == pending_favored &&
        prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
        prev_qc == queue_cycle && prev_uc == unique_crashes &&
        prev_uh == unique_hangs && prev_md == max_depth) return;

    prev_qp  = queued_paths;
    prev_pf  = pending_favored;
    prev_pnf = pending_not_fuzzed;
    prev_ce  = current_entry;
    prev_qc  = queue_cycle;
    prev_uc  = unique_crashes;
    prev_uh  = unique_hangs;
    prev_md  = max_depth;

    /* Fields in the file:

       unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
       favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
       execs_per_sec */

    fprintf(plot_file,
            "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
            Util::GetCurTimeMs() / 1000, queue_cycle - 1, current_entry, queued_paths,
            pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
            unique_hangs, max_depth, eps); /* ignore errors */

    fflush(plot_file);
}

template<class Testcase>
void AFLStateTemplate<Testcase>::SaveCmdline(const std::vector<std::string> &argv) {
    for (u32 i=0; i < argv.size(); i++) {
        if (i > 0) orig_cmdline += ' ';
        orig_cmdline += argv[i];
    }
}

template<class Testcase>
void AFLStateTemplate<Testcase>::FixUpBanner(const std::string &name) {
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

template<class Testcase>
void AFLStateTemplate<Testcase>::CheckIfTty(void) {
    struct winsize ws;

    if (getenv("AFL_NO_UI")) {
        OKF("Disabling the UI because AFL_NO_UI is set.");
        not_on_tty = 1;
        return;
    }

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws)) {
        if (errno == ENOTTY) {
            OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
            not_on_tty = 1;
        }

        return;
    }
}

static void ShufflePtrs(void** ptrs, u32 cnt, int rand_fd) {
    for (u32 i=0; i < cnt-2; i++) {
        u32 j = i + util::UR(cnt - i, rand_fd);
        std::swap(ptrs[i], ptrs[j]);
    }
}

template<class Testcase>
void AFLStateTemplate<Testcase>::ReadTestcases(void) {
    //FIXME: support resume
    struct dirent **nl;

    auto& in_dir = setting->in_dir;
    ACTF("Scanning '%s'...", in_dir.c_str());

    /* We use scandir() + alphasort() rather than readdir() because otherwise,
       the ordering  of test cases would vary somewhat randomly and would be
       difficult to control. */

    int nl_cnt = Util::ScanDirAlpha(in_dir.string(), &nl);
    if (nl_cnt < 0) {
        MSG("\n" cLRD "[-] " cRST
            "The input directory does not seem to be valid - try again. The fuzzer needs\n"
            "    one or more test case to start with - ideally, a small file under 1 kB\n"
            "    or so. The cases must be stored as regular files directly in the input\n"
            "    directory.\n");

        ERROR("Unable to open '%s'", in_dir.c_str());
    }

    if (shuffle_queue && nl_cnt > 1) {
        ACTF("Shuffling queue...");
        ShufflePtrs((void**)nl, nl_cnt, rand_fd);
    }

    for (int i=0; i < nl_cnt; i++) {
        struct stat st;

        std::string fn = Util::StrPrintf("%s/%s", in_dir.c_str(), nl[i]->d_name);
        std::string dfn = Util::StrPrintf("%s/.state/deterministic_done/%s", in_dir.c_str(), nl[i]->d_name);

        bool passed_det = false;
        free(nl[i]); /* not tracked */

        if (lstat(fn.c_str(), &st) != 0 || access(fn.c_str(), R_OK) != 0) {
            ERROR("Unable to access '%s'", fn.c_str());
        }

        /* This also takes care of . and .. */

        if (!S_ISREG(st.st_mode) || !st.st_size || fn.find("/README.txt") != std::string::npos) {
            continue;
        }

        if (st.st_size > option::GetMaxFile<Tag>()) {
            EXIT("Test case '%s' is too big (%s, limit is %s)",
                fn.c_str(),
                util::DescribeMemorySize(st.st_size).c_str(),
                util::DescribeMemorySize(option::GetMaxFile<Tag>()).c_str()
            );
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
             "Looks like there are no valid test cases in the input directory! The fuzzer\n"
             "    needs one or more test case to start with - ideally, a small file under\n"
             "    1 kB or so. The cases must be stored as regular files directly in the\n"
             "    input directory.\n");

        EXIT("No usable test cases in '%s'", in_dir.c_str());
    }

    last_path_time = 0;
    queued_at_start = queued_paths;
}

template<class Testcase>
void AFLStateTemplate<Testcase>::PivotInputs() {
    ACTF("Creating hard links for all input files...");

    u32 id = 0;
    for (const auto& testcase : case_queue) {
        auto& input = *testcase->input;

        std::string rsl = input.GetPath().filename().string();

        const std::string case_prefix = setting->simple_files ? "id_" : "id:";

        u32 orig_id;
        std::string nfn;
        if ( rsl.substr(0, 3) == case_prefix
          && sscanf(rsl.c_str()+3, "%06u", &orig_id) == 1
          && orig_id == id) {
            resuming_fuzz = true;
            nfn = Util::StrPrintf("%s/queue/%s", setting->out_dir.c_str(), rsl.c_str());

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

template<class Tag>
static void CheckMapCoverage(const InplaceMemoryFeedback &inp_feed) {
    if (inp_feed.CountNonZeroBytes() < 100) return ;

    inp_feed.ShowMemoryToFunc(
        [](const u8 *trace_bits, u32 /* map_size */) {
            u32 start = 1 << (option::GetMapSizePow2<Tag>() - 1);
            for (u32 i = start; i < option::GetMapSize<Tag>(); i++) {
                if (trace_bits[i]) return;
            }

            WARNF("Recompile binary with newer version of afl to improve coverage!");
        }
    );
}

template<class Testcase>
void AFLStateTemplate<Testcase>::PerformDryRun() {
    u32 cal_failures = 0;
    char *skip_crashes = getenv("AFL_SKIP_CRASHES");

    for (const auto& testcase : case_queue) {
        auto& input = *testcase->input;

        std::string fn = input.GetPath().filename().string();

        ACTF("Attempting dry run with '%s'...", fn.c_str());

        input.Load();

        // There should be no active instance of InplaceMemoryFeedback at this point.
        // So we can just create a temporary instance to get a result.
        InplaceMemoryFeedback inp_feed;
        ExitStatusFeedback exit_status;
        PUTExitReasonType res = CalibrateCaseWithFeedDestroyed(
                                    *testcase,
                                    input.GetBuf(),
                                    input.GetLen(),
                                    inp_feed,
                                    exit_status,
                                    0,
                                    true);

        input.Unload();

        if (stop_soon) return;

        if (res == crash_mode || res == PUTExitReasonType::FAULT_NOBITS) {
            MSG(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST,
                 input.GetLen(), testcase->bitmap_size, testcase->exec_us);
        }

        switch (res) {
        case PUTExitReasonType::FAULT_NONE:
            if (testcase == case_queue.front()) {
                CheckMapCoverage<typename Testcase::Tag>(inp_feed);
            }

            if (crash_mode != PUTExitReasonType::FAULT_NONE) {
                EXIT("Test case '%s' does *NOT* crash", fn.c_str());
            }

            break;

        case PUTExitReasonType::FAULT_TMOUT:

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
                     "The program took more than %u ms to process one of the initial test cases.\n"
                     "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
                     "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
                     "    what you are doing and want to simply skip the unruly test cases, append\n"
                     "    '+' at the end of the value passed to -t ('-t %u+').\n",
                     setting->exec_timelimit_ms,
                     setting->exec_timelimit_ms);

                EXIT("Test case '%s' results in a timeout", fn.c_str());
            } else {
                MSG("\n" cLRD "[-] " cRST
                     "The program took more than %u ms to process one of the initial test cases.\n"
                     "    This is bad news; raising the limit with the -t option is possible, but\n"
                     "    will probably make the fuzzing process extremely slow.\n\n"

                     "    If this test case is just a fluke, the other option is to just avoid it\n"
                     "    altogether, and find one that is less of a CPU hog.\n",
                     setting->exec_timelimit_ms);

                EXIT("Test case '%s' results in a timeout", fn.c_str());
            }

        case PUTExitReasonType::FAULT_CRASH:

            if (crash_mode == PUTExitReasonType::FAULT_CRASH) break;

            if (skip_crashes) {
                WARNF("Test case results in a crash (skipping)");
                testcase->cal_failed = option::GetCalChances(*this);
                cal_failures++;
                break;
            }

            if (setting->exec_memlimit > 0) {
                MSG("\n" cLRD "[-] " cRST
                    "Oops, the program crashed with one of the test cases provided. There are\n"
                    "    several possible explanations:\n\n"

                    "    - The test case causes known crashes under normal working conditions. If\n"
                    "      so, please remove it. The fuzzer should be seeded with interesting\n"
                    "      inputs - but not ones that cause an outright crash.\n\n"

                    "    - The current memory limit (%s) is too low for this program, causing\n"
                    "      it to die due to OOM when parsing valid files. To fix this, try\n"
                    "      bumping it up with the -m setting in the command line. If in doubt,\n"
                    "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
                    "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
                    "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

                    "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
                    "      estimate the required amount of virtual memory for the binary. Also,\n"
                    "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__

                    "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
                    "      break afl-fuzz performance optimizations when running platform-specific\n"
                    "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

                    "",
                    util::DescribeMemorySize(setting->exec_memlimit << 20).c_str(),
                    setting->exec_memlimit - 1,
                    "docs"
                );
            } else {
                MSG("\n" cLRD "[-] " cRST
                    "Oops, the program crashed with one of the test cases provided. There are\n"
                    "    several possible explanations:\n\n"

                    "    - The test case causes known crashes under normal working conditions. If\n"
                    "      so, please remove it. The fuzzer should be seeded with interesting\n"
                    "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__

                    "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
                    "      break afl-fuzz performance optimizations when running platform-specific\n"
                    "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

                );
            }

            EXIT("Test case '%s' results in a crash", fn.c_str());

        case PUTExitReasonType::FAULT_ERROR:

            EXIT("Unable to execute target application ('%s')",
                setting->argv[0].c_str());

        case PUTExitReasonType::FAULT_NOINST:

            EXIT("No instrumentation detected");

        case PUTExitReasonType::FAULT_NOBITS:

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

template<class Testcase>
void AFLStateTemplate<Testcase>::ShowStats(void) {
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

        term_too_small = CheckTermSize();
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
    u32 banner_len =  (crash_mode != PUTExitReasonType::FAULT_NONE ? 24 : 22)
                    + strlen(GetVersion(*this)) + use_banner.size();
    u32 banner_pad = (80 - banner_len) / 2;

    auto fuzzer_name = crash_mode != PUTExitReasonType::FAULT_NONE ?
                          cPIN "fuzzuf peruvian were-rabbit"
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
         "  cycles done : %s%-5s  " bSTG bV "\n",
         DescribeTimeDelta(cur_ms, start_time).c_str(), col.c_str(),
         DescribeInteger(queue_cycle - 1).c_str());

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

    if (avg_exec < 100) {
        tmp = DescribeFloat(avg_exec) + "/sec (";
        if (avg_exec < 20) tmp += "zzzz...";
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

    /* Aaaalmost there... hold on! */

    MSG(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
         bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

    // In original AFL, the following part is unrolled, which is too long.
    // So put them into a loop as many as possible and wish compiler's optimization.

    // First, define the type describing the information output in one line:
    using OnelineInfo = std::tuple<
        const char *, // mut_name.      e.g. "bit flips", "arithmetics"
        const char *, // neighbor_name. e.g. "levels", "pending", "pend fav"
        std::string,  // neighbor_val.  e.g. DI(max_depth), DI(pending_not_fuzzed), DI(pending_favored)
        u8,           // stage1.        e.g. STAGE_FLIP8, STAGE_ARITH8
        u8,           // stage2.        e.g. STAGE_FLIP16, STAGE_ARITH16
        u8            // stage3.        e.g. STAGE_FLIP32, STAGE_ARITH32
    >;

    // Next, define each lines
    OnelineInfo line_infos[] = {
        { "   bit flips", "    levels", DescribeInteger(max_depth),
          STAGE_FLIP1, STAGE_FLIP2, STAGE_FLIP4 },
        { "  byte flips", "   pending", DescribeInteger(pending_not_fuzzed),
          STAGE_FLIP8, STAGE_FLIP16, STAGE_FLIP32 },
        { " arithmetics", "  pend fav", DescribeInteger(pending_favored),
          STAGE_ARITH8, STAGE_ARITH16, STAGE_ARITH32 },
        { "  known ints", " own finds", DescribeInteger(queued_discovered),
          STAGE_INTEREST8, STAGE_INTEREST16, STAGE_INTEREST32 },
        { "  dictionary", "  imported", sync_id.empty() ? "n/a" : DescribeInteger(queued_imported),
          STAGE_EXTRAS_UO, STAGE_EXTRAS_UI, STAGE_EXTRAS_AO }
    }; // Havoc is difficult to put together

    tmp = "n/a, n/a, n/a";
    for (int i=0; i<5; i++) {
        auto [mut_name, neighbor_name, neighbor_val, stage1, stage2, stage3]
            = line_infos[i];

        if (!skip_deterministic) {
            tmp =        DescribeInteger(stage_finds [stage1]) +
                   '/' + DescribeInteger(stage_cycles[stage1]) +

                  ", " + DescribeInteger(stage_finds [stage2]) +
                   '/' + DescribeInteger(stage_cycles[stage2]) +

                  ", " + DescribeInteger(stage_finds [stage3]) +
                   '/' + DescribeInteger(stage_cycles[stage3]);
        }

        MSG(bV bSTOP "%s : " cRST "%-37s " bSTG bV bSTOP "%s : "
             cRST "%-10s " bSTG bV "\n",
             mut_name, tmp.c_str(), neighbor_name, neighbor_val.c_str());
    }

    tmp =        DescribeInteger(stage_finds [STAGE_HAVOC]) +
           '/' + DescribeInteger(stage_cycles[STAGE_HAVOC]) +

          ", " + DescribeInteger(stage_finds [STAGE_SPLICE]) +
           '/' + DescribeInteger(stage_cycles[STAGE_SPLICE]);

    MSG(bV bSTOP "       havoc : " cRST "%-37s " bSTG bV bSTOP, tmp.c_str());

    if (t_bytes) tmp = Util::StrPrintf("%0.02f%%", stab_ratio);
    else tmp = "n/a";

    MSG(" stability : %s%-10s " bSTG bV "\n", (stab_ratio < 85 && var_byte_count > 40)
         ? cLRD : ((queued_variable && (!persistent_mode || var_byte_count > 20))
         ? cMGN : cRST), tmp.c_str());

    if (!bytes_trim_out) {
        tmp = "n/a, ";
    } else {
        tmp = Util::StrPrintf("%0.02f%%",
                ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in);
        tmp += "/" + DescribeInteger(trim_execs) + ", ";
    }

    if (!blocks_eff_total) {
        tmp += "n/a";
    } else {
        tmp += Util::StrPrintf("%0.02f%%",
                ((double)(blocks_eff_total - blocks_eff_select)) * 100 / blocks_eff_total);
    }

    MSG(bV bSTOP "        trim : " cRST "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n"
         bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp.c_str());

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
            MSG(SP10 cGRA "[cpu%03d:%s%3u%%" cGRA "]\r" cRST,
                 std::min(executor->binded_cpuid.value(), 999),
                 cpu_color.c_str(), std::min(cur_utilization, 999u));
        } else {
            MSG(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
                 cpu_color.c_str(), std::min(cur_utilization, 999u));
        }

#else

        MSG(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
             cpu_color.c_str(), std::min(cur_utilization, 999u));

#endif /* ^HAVE_AFFINITY */

    } else MSG("\r");

    /* Hallelujah! */

    fflush(0);
}

template<class Testcase>
void AFLStateTemplate<Testcase>::ReceiveStopSignal(void) {
    stop_soon = 1;
    executor->ReceiveStopSignal();
}

template<class Testcase>
bool AFLStateTemplate<Testcase>::ShouldConstructAutoDict(void) {
    return should_construct_auto_dict;
}

template<class Testcase>
void AFLStateTemplate<Testcase>::SetShouldConstructAutoDict(bool v) {
    should_construct_auto_dict = v;
}

} // namespace fuzzuf::algorithm::afl
