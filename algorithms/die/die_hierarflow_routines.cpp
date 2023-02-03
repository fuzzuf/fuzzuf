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
 * @file die_fuzzer.cpp
 * @brief HierarFlow routine of DIE
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/die/die_hierarflow_routines.hpp"

#include <string>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/algorithms/die/die_state.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::die::routine::mutation {

/**
 * @fn
 * @brief Call esfuzz to mutate a testcase
 * @param (testcase) Testcase to mutate
 */
DIEMutCalleeRef DIEMutate::operator()(std::shared_ptr<DIETestcase> testcase) {
  int fd;
  u8 *buf_js, *buf_ty;
  u32 len_js, len_ty;
  std::vector<std::string> cmd;

  fs::path path_die = fs::absolute(state.setting->die_dir);
  fs::path path_esfuzz = path_die / "fuzz/TS/esfuzz.js";
  fs::path path_mutate = state.setting->out_dir / "mutated";

  /* Update status */
  state.stage_short = "DIE";
  state.stage_name = "DIE";

  /* Generate a seed used in esfuzz */
  u32 seed = afl::util::UR(UINT32_MAX, state.rand_fd);

  /* Number of scripts to generate in this mutation */
  int mut_cnt = state.setting->mut_cnt;

  state.stage_cur = 0;
  state.stage_max = mut_cnt;

  /* Call esfuzz to mutate testcase */
  cmd = {
      "timeout",
      "30",
      state.setting->cmd_node,
      path_esfuzz.string(),                 // Path to esfuzz.js
      testcase->input->GetPath().string(),  // Input JS
      path_mutate.string(),                 // Output directory
      afl::util::DescribeInteger(mut_cnt),  // Number of mutation
      afl::util::DescribeInteger(seed)      // Seed
  };
  fuzzuf::utils::ExecuteCommand(cmd);

  /* Add generated files to queue */
  for (int n = 0; n < mut_cnt; n++) {
    state.stage_cur++;

    /* Create path string of output js and type files */
    fs::path path_js =
        fuzzuf::utils::StrPrintf("%s/%d.js", path_mutate.c_str(), n);
    fs::path path_type = path_js.string() + ".t";

    if (!fs::exists(path_js) || !fs::exists(path_type)) {
      /* esfuzz died for some reason */
      continue;
    }

    len_js = fs::file_size(path_js);
    len_ty = fs::file_size(path_type);
    if (len_js == 0 || len_ty == 0) {
      /* esfuzz couldn't write file for some reason */
      continue;
    }

    /* Load JS file */
    fd = fuzzuf::utils::OpenFile(path_js.string(), O_RDONLY);
    buf_js = static_cast<u8*>(
        mmap(nullptr, len_js, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
    fuzzuf::utils::CloseFile(fd);

    if (buf_js == MAP_FAILED) {
      ERROR("Unable to mmap '%s' : %s", path_js.c_str(), strerror(errno));
    }

    /* Load type file */
    fd = fuzzuf::utils::OpenFile(path_type.string(), O_RDONLY);
    buf_ty = static_cast<u8*>(
        mmap(nullptr, len_ty, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
    fuzzuf::utils::CloseFile(fd);

    if (buf_ty == MAP_FAILED) {
      ERROR("Unable to mmap '%s' : %s", path_type.c_str(), strerror(errno));
    }

    /* Execute PUT */
    if (this->CallSuccessors(buf_js, len_js, buf_ty, len_ty)) {
      munmap(buf_js, len_js);
      munmap(buf_ty, len_ty);
      return this->GoToParent();
    }

    munmap(buf_js, len_js);
    munmap(buf_ty, len_ty);
  }

  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::die::routine::mutation

namespace fuzzuf::algorithm::die::routine::other {

/**
 * @fn
 * @brief Execute mutated testcase
 * @param (buf_js) Content of JavaScript file
 * @param (len_js) Size of JavaScript file
 * @param (buf_ty) Content of type file
 * @param (len_ty) Size of type file
 */
DIEExecCalleeRef DIEExecute::operator()(const u8* buf_js,
                                        u32 len_js,  // js file
                                        const u8* buf_ty,
                                        u32 len_ty  // type file
) {
  feedback::ExitStatusFeedback exit_status;

  /* Execution is the same as that of AFL */
  auto inp_feed =
      state.RunExecutorWithClassifyCounts(buf_js, len_js, exit_status);

  /* But we pass type file as well as JavaScript */
  CallSuccessors(buf_js, len_js, buf_ty, len_ty, inp_feed, exit_status);

  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::die::routine::other

namespace fuzzuf::algorithm::die::routine::update {

/**
 * @fn
 * @brief Save mutated testcase
 * @param (buf_js) Content of JavaScript file
 * @param (len_js) Size of JavaScript file
 * @param (buf_ty) Content of type file
 * @param (len_ty) Size of type file
 * @param (inp_feed) Inplace memory feedback
 * @param (exit_status) Exit status
 */
DIEUpdateCalleeRef DIEUpdate::operator()(
    const u8* buf_js, u32 len_js,  // js file
    const u8* buf_ty, u32 len_ty,  // type file
    feedback::InplaceMemoryFeedback& inp_feed,
    feedback::ExitStatusFeedback& exit_status) {
  if (state.stop_soon) {
    return GoToParent();
  }

  if (exit_status.exit_reason == feedback::PUTExitReasonType::FAULT_TMOUT) {
    if (state.subseq_tmouts++ > afl::option::GetTmoutLimit(state)) {
      state.cur_skipped_paths++;
      return GoToParent();
    }
  } else
    state.subseq_tmouts = 0;

  /* Don't forget to save type file as well as js file */
  if (state.SaveIfInteresting(buf_js, len_js, buf_ty, len_ty, inp_feed,
                              exit_status)) {
    state.queued_discovered++;
  }

  if (state.stage_cur % state.stats_update_freq == 0 ||
      state.stage_cur + 1 == state.stage_max) {
    state.ShowStats();
  }

  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::die::routine::update
