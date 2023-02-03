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
/**
 * @file VUzzerState.cpp
 * @brief Global state used during hieraflow loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/vuzzer/vuzzer_state.hpp"

#include <sys/ioctl.h>
#include <unistd.h>

#include "fuzzuf/algorithms/vuzzer/vuzzer.hpp"
#include "fuzzuf/executor/pintool_executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::vuzzer {

// FIXME: check if we are initializing all the members that need to be
// initialized
VUzzerState::VUzzerState(
    std::shared_ptr<const VUzzerSetting> setting,
    std::shared_ptr<fuzzuf::executor::PinToolExecutor> executor,
    std::shared_ptr<fuzzuf::executor::PolyTrackerExecutor> texecutor)
    : setting(setting),
      executor(executor),
      taint_executor(texecutor),
      all_chars_dict(256),
      high_chars_dict(128) {
  /* Build 255 dictionaries with characters \x0, \x1 .... \x255 */
  for (u32 c = 0; c < all_chars_dict.size(); c++) {
    all_chars_dict[c].data.emplace_back((u8)c);
  }
  /* Build 128 dictionaries with characters \x128, \x129 .... \x255 */
  for (u32 c = 0; c < high_chars_dict.size(); c++) {
    high_chars_dict[c].data.emplace_back((u8)(c + 128));
  }

  keepfilenum = setting->keep_num_of_seed_queue;
}

VUzzerState::~VUzzerState() {}

/**
 * @brief Execute a PUT with input from the buffer
 * @param (buf) Input buffer
 * @param (len) Length of the input buffer
 * @param (exit_status) Exit status of the execution
 * @param (tmout) Timeout setting for the executor
 */
feedback::FileFeedback VUzzerState::RunExecutor(
    const u8 *buf, u32 len, feedback::ExitStatusFeedback &exit_status,
    u32 tmout) {
  if (tmout == 0) {
    executor->Run(buf, len);
  } else {
    executor->Run(buf, len, tmout);
  }

  auto inp_feed = executor->GetFileFeedback("bb.out");
  exit_status = executor->GetExitStatusFeedback();

  return feedback::FileFeedback(std::move(inp_feed));
}

/**
 * Execute a PUT by dynamic taint analysis technique with input from the buffer.
 * The input buffer is marked as taint tag.
 * @brief Execute a PUT by dynamic taint analysis technique with input from the
 * buffer.
 * @param (buf) Input buffer
 * @param (len) Length of the input buffer
 * @param (exit_status) Exit status of the execution
 * @param (tmout) Timeout setting for the executor
 */
feedback::FileFeedback VUzzerState::RunTaintExecutor(
    const u8 *buf, u32 len, feedback::ExitStatusFeedback &exit_status,
    u32 tmout) {
  if (tmout == 0) {
    taint_executor->Run(buf, len);
  } else {
    taint_executor->Run(buf, len, tmout);
  }

  auto inp_feed = executor->GetFileFeedback(setting->path_to_taint_file);
  exit_status = executor->GetExitStatusFeedback();

  return feedback::FileFeedback(std::move(inp_feed));
}

void VUzzerState::ReceiveStopSignal(void) {
  stop_soon = 1;
  executor->ReceiveStopSignal();
  taint_executor->ReceiveStopSignal();
}

/**
 *
 * @brief Load initial seeds from dir specified by -i option
 */
void VUzzerState::ReadTestcases(void) {
  struct dirent **nl;

  auto in_dir = fs::canonical(setting->in_dir);  // Get aboslute path
  MSG("Scanning '%s'...", in_dir.c_str());

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

  for (int i = 0; i < nl_cnt; i++) {
    struct stat st;

    std::string fn =
        fuzzuf::utils::StrPrintf("%s/%s", in_dir.c_str(), nl[i]->d_name);

    free(nl[i]); /* not tracked */

    if (lstat(fn.c_str(), &st) != 0 || access(fn.c_str(), R_OK) != 0) {
      ERROR("Unable to access '%s'", fn.c_str());
    }

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size ||
        fn.find("/README.txt") != std::string::npos) {
      continue;
    }

#if 0
        if (st.st_size > VUzzerOption::MAX_FILE) {
            EXIT("Test case '%s' is too big (%s, limit is %s)",
                fn.c_str(),
                VUzzer::util::DescribeMemorySize(st.st_size).c_str(),
                VUzzer::util::DescribeMemorySize(VUzzerOption::MAX_FILE).c_str()
            );
        }
#endif

    AddToQueue(pending_queue, fn, nullptr, (u32)st.st_size);
  }

  free(nl); /* not tracked */

  if (pending_queue.empty()) {
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
}

/**
 * @brief Add a new testcase to seed queue
 * @param (queue) seed queue
 * @param (fn) file name of testcase
 * @param (buf) the buffer that will be written to the testcase file. If you
 * don't want to overwrite the file, specify nullptr.
 * @param (len) size of input buffer
 * @return Pointer to a new seed
 */
std::shared_ptr<VUzzerTestcase> VUzzerState::AddToQueue(
    std::vector<std::shared_ptr<VUzzerTestcase>> &queue, const std::string &fn,
    const u8 *buf, u32 len) {
  auto input = input_set.CreateOnDisk(fn);
  if (buf) {
    input->OverwriteThenUnload(buf, len);
  }

  std::shared_ptr<VUzzerTestcase> testcase(
      new VUzzerTestcase(std::move(input)));

  queued_paths++;  // XXX: Propose new solution for id management
  queue.emplace_back(testcase);
  return testcase;
}

/**
 * @brief Delete the testcase from seed queue
 * @param (queue) Seed queue
 * @param (itr) Iterator of seed entry
 * @return Iterator of the entry next to deleted one
 */
std::vector<std::shared_ptr<VUzzerTestcase>>::iterator
VUzzerState::DeleteFromQueue(
    std::vector<std::shared_ptr<VUzzerTestcase>> &queue,
    std::vector<std::shared_ptr<VUzzerTestcase>>::iterator &itr) {
  input_set.erase((*itr)->input->GetID());  // Delete from ExecInputSet
  return queue.erase(itr);                  // Delete from seed queue
}

}  // namespace fuzzuf::algorithm::vuzzer
