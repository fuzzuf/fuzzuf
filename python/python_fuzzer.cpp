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
#include "fuzzuf/python/python_fuzzer.hpp"

#include <cstddef>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/python/python_hierarflow_routines.hpp"
#include "fuzzuf/python/python_state.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::bindings::python {

// FIXME: move the following into namespace fuzzuf::bindings::python

// NOTE: 流石に雑すぎる
void PythonFuzzer::ExecuteInitialSeeds(const fs::path& in_dir) {
  struct dirent** namelist;

  DEBUG("Scanning %s\n", in_dir.c_str());

  int dirnum = fuzzuf::utils::ScanDirAlpha(in_dir.string(), &namelist);
  if (dirnum < 0) {
    ERROR("Unable to open '%s'", in_dir.c_str());
  }

  for (int i = 0; i < dirnum; i++) {
    struct stat st;

    std::string fn =
        fuzzuf::utils::StrPrintf("%s/%s", in_dir.c_str(), namelist[i]->d_name);

    free(namelist[i]); /* not tracked */

    if (lstat(fn.c_str(), &st) != 0 || access(fn.c_str(), R_OK) != 0) {
      ERROR("Unable to access '%s'", fn.c_str());
    }

    /* This also takes care of `.` and `..` */

    if (!S_ISREG(st.st_mode) || !st.st_size) {
      continue;
    }

    using fuzzuf::algorithm::afl::option::GetMaxFile;
    if (st.st_size > GetMaxFile<PythonTag>()) {
      ERROR("Test case '%s' is too big\n", fn.c_str());
    }

    DEBUG("Attempting dry run with '%s'...\n", fn.c_str());

    auto buf = std::make_unique<u8[]>(st.st_size);
    int fd = fuzzuf::utils::OpenFile(fn, O_RDONLY);
    fuzzuf::utils::ReadFile(fd, buf.get(), st.st_size);
    fuzzuf::utils::CloseFile(fd);
    add_seed(buf.get(), st.st_size);
  }

  free(namelist);
}

PythonFuzzer::PythonFuzzer(const std::vector<std::string>& argv,
                           const std::string& in_dir,
                           const std::string& out_dir, u32 exec_timelimit_ms,
                           u32 exec_memlimit, bool forksrv, bool need_afl_cov,
                           bool need_bb_cov)
    : setting(argv, in_dir, out_dir, exec_timelimit_ms, exec_memlimit, forksrv,
              need_afl_cov, need_bb_cov),
      state(new PythonState(setting))
// Executor and FuzzingPrimitive will be initialized inside the function
{
  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;

  fuzzuf::utils::set_segv_handler::get();

  // Executor needs the directory specified by "out_dir" to be already set up
  // so we need to create the directory first, and then initialize Executor
  fuzzuf::utils::SetupDirs(setting.out_dir.string());

  executor.reset(new fuzzuf::executor::NativeLinuxExecutor(
      setting.argv, setting.exec_timelimit_ms, setting.exec_memlimit,
      setting.forksrv, setting.out_dir / GetDefaultOutfile<PythonTag>(),
      setting.need_afl_cov ? GetMapSize<PythonTag>() : 0,
      setting.need_bb_cov ? GetMapSize<PythonTag>() : 0));

  BuildFuzzFlow();

  ExecuteInitialSeeds(setting.in_dir);
}

PythonFuzzer::~PythonFuzzer() {}

// do not call non aync-signal-safe functions inside because this function can
// be called during signal handling
void PythonFuzzer::ReceiveStopSignal(void) { executor->ReceiveStopSignal(); }

void PythonFuzzer::Reset(void) {
  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;

  // すべてを確保した逆順で開放し、out_dirを初期化し、再度すべて確保し直す

  executor.reset();

  fuzzuf::utils::DeleteFileOrDirectory(setting.out_dir.string());
  fuzzuf::utils::SetupDirs(setting.out_dir.string());

  state.reset(new PythonState(setting));

  executor.reset(new fuzzuf::executor::NativeLinuxExecutor(
      setting.argv, setting.exec_timelimit_ms, setting.exec_memlimit,
      setting.forksrv, setting.out_dir / GetDefaultOutfile<PythonTag>(),
      setting.need_afl_cov ? GetMapSize<PythonTag>() : 0,
      setting.need_bb_cov ? GetMapSize<PythonTag>() : 0));

  BuildFuzzFlow();

  ExecuteInitialSeeds(setting.in_dir);
}

void PythonFuzzer::Release(void) {
  executor.reset();
  state.reset();

  // move HierarFlowNodes to local variables to call destructor
  { auto _ = std::move(bit_flip); }
  { auto _ = std::move(byte_flip); }
  { auto _ = std::move(havoc); }
  { auto _ = std::move(add); }
  { auto _ = std::move(sub); }
  { auto _ = std::move(interest); }
  { auto _ = std::move(add_seed); }

  fuzzuf::utils::DeleteFileOrDirectory(setting.out_dir.string());
}

void PythonFuzzer::BuildFuzzFlow() {
  using namespace fuzzuf::bindings::python::routine;

  using fuzzuf::hierarflow::CreateNode;
  using fuzzuf::hierarflow::WrapToMakeHeadNode;

  auto execute = CreateNode<PyExecutePUT>(*executor);
  auto update = CreateNode<PyUpdate>(*state);
  bit_flip = CreateNode<PyBitFlip>(*state);
  byte_flip = CreateNode<PyByteFlip>(*state);
  havoc = CreateNode<PyHavoc>(*state);
  add = CreateNode<PyAdd>(*state);
  sub = CreateNode<PySub>(*state);
  interest = CreateNode<PyInterest>(*state);
  overwrite = CreateNode<PyOverwrite>(*state);

  bit_flip << execute << update;
  byte_flip << execute.HardLink() << update.HardLink();
  havoc << execute.HardLink() << update.HardLink();
  add << execute.HardLink() << update.HardLink();
  sub << execute.HardLink() << update.HardLink();
  interest << execute.HardLink() << update.HardLink();
  overwrite << execute.HardLink() << update.HardLink();

  auto execute_for_add_seed = execute.HardLink();
  execute_for_add_seed << update.HardLink();
  add_seed = WrapToMakeHeadNode(execute_for_add_seed);
}

u64 PythonFuzzer::FlipBit(u32 pos, u32 len) {
  assert(state->mutator != nullptr);
  bit_flip(pos, len);
  state->mutator.reset();
  return bit_flip->GetResponseValue();
}

u64 PythonFuzzer::FlipByte(u32 pos, u32 len) {
  assert(state->mutator != nullptr);
  byte_flip(pos, len);
  state->mutator.reset();
  return byte_flip->GetResponseValue();
}

u64 PythonFuzzer::Havoc(u32 stacking) {
  assert(state->mutator != nullptr);
  havoc(stacking);
  state->mutator.reset();
  return havoc->GetResponseValue();
}

u64 PythonFuzzer::Add(u32 pos, int val, int bits, bool be) {
  assert(state->mutator != nullptr);
  add(pos, val, bits, be);
  state->mutator.reset();
  return add->GetResponseValue();
}

u64 PythonFuzzer::Sub(u32 pos, int val, int bits, bool be) {
  assert(state->mutator != nullptr);
  sub(pos, val, bits, be);
  state->mutator.reset();
  return sub->GetResponseValue();
}

u64 PythonFuzzer::Interest(u32 pos, int bits, int idx, bool be) {
  assert(state->mutator != nullptr);
  interest(pos, bits, idx, be);
  state->mutator.reset();
  return interest->GetResponseValue();
}

u64 PythonFuzzer::Overwrite(u32 pos, char chr) {
  assert(state->mutator != nullptr);
  overwrite(pos, chr);
  state->mutator.reset();
  return overwrite->GetResponseValue();
}

u64 PythonFuzzer::AddSeed(u32 len, const std::vector<u8>& buf) {
  assert(len == buf.size());
  add_seed(buf.data(), buf.size());
  return add_seed->GetResponseValue();
}

void PythonFuzzer::SelectSeed(u64 seed_id) {
  auto itr = state->test_set.find(seed_id);
  if (itr == state->test_set.end()) ERROR("specified seed ID is not found");

  state->mutator.reset(new mutator::Mutator<PythonTag>(*itr->second->input));
}

void PythonFuzzer::RemoveSeed(u64 seed_id) {
  auto itr = state->test_set.find(seed_id);
  if (itr == state->test_set.end()) ERROR("specified seed ID is not found");

  state->input_set.erase(seed_id);
  state->test_set.erase(seed_id);
}

std::vector<u64> PythonFuzzer::GetSeedIDs(void) {
  return state->input_set.get_ids();
}

std::optional<PySeed> PythonFuzzer::GetPySeed(u64 seed_id) {
  auto itr = state->test_set.find(seed_id);
  if (itr == state->test_set.end()) return std::nullopt;

  auto& testcase = *itr->second;
  auto& input = *testcase.input;
  return PySeed(
      seed_id, std::vector<u8>(input.GetBuf(), input.GetBuf() + input.GetLen()),
      testcase.bb_feed.GetTrace(), testcase.afl_feed.GetTrace());
}

std::vector<std::unordered_map<int, u8>> PythonFuzzer::GetAFLTraces(void) {
  std::vector<std::unordered_map<int, u8>> ret;
  for (auto& itr : state->test_set)
    ret.emplace_back(itr.second->afl_feed.GetTrace());
  return ret;
}

std::vector<std::unordered_map<int, u8>> PythonFuzzer::GetBBTraces(void) {
  std::vector<std::unordered_map<int, u8>> ret;
  for (auto& itr : state->test_set)
    ret.emplace_back(itr.second->bb_feed.GetTrace());
  return ret;
}

void PythonFuzzer::SuppressLog() {
  utils::runlevel = utils::RunLevel::MODE_RELEASE;
}

void PythonFuzzer::ShowLog() { utils::runlevel = utils::RunLevel::MODE_DEBUG; }

}  // namespace fuzzuf::bindings::python
