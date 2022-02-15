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
 * @file state.cpp
 * @brief Global state used during hieraflow loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <chrono>
#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/persistent_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer {

NautilusState::NautilusState(
    std::shared_ptr<const NautilusSetting> setting,
    std::shared_ptr<NativeLinuxExecutor> executor
) : setting (setting),
    executor (executor),
    queue (setting->path_to_workdir),
    execution_count (0),
    average_executions_per_sec (0),
    bits_found_by_havoc (0),
    bits_found_by_havoc_rec (0),
    bits_found_by_min (0),
    bits_found_by_min_rec (0),
    bits_found_by_splice (0),
    bits_found_by_det (0),
    bits_found_by_gen (0),
    asan_found_by_havoc (0),
    asan_found_by_havoc_rec (0),
    asan_found_by_min (0),
    asan_found_by_min_rec (0),
    asan_found_by_splice (0),
    asan_found_by_det (0),
    asan_found_by_gen (0),
    last_found_asan ("Not found yet."),
    last_found_sig ("Not found yet."),
    last_timeout ("No timeout yet."),
    state_saved ("State not saved yet."),
    total_found_asan (0),
    total_found_sig (0)
{
  bitmaps[false] = std::vector<uint8_t>(setting->bitmap_size, 0);
  bitmaps[true]  = std::vector<uint8_t>(setting->bitmap_size, 0);

  // TODO: fix here
  executor = executor;
}

/**
 * @fn
 * @brief Run testcase after checking deplication
 * @param (tree) Tree of testcase
 * @param (exec_reason) Execution reason
 * @param (ctx) Context
 */
void NautilusState::RunOnWithDedup(const TreeLike& tree,
                                   ExecutionReason exec_reason,
                                   Context &ctx) {
  std::string code = tree.UnparseToVec(ctx);

  /* Check if input is known */
  if (last_tried_inputs.find(code) != last_tried_inputs.end()) {
    return;
  } else {
    last_tried_inputs.insert(code);

    if (last_inputs_ring_buffer.size() == 10000) {
      /* If queue is big, remove code from both vector and deque */
      last_tried_inputs.erase(last_inputs_ring_buffer.back());
      last_inputs_ring_buffer.pop_back();
      last_inputs_ring_buffer.push_front(code);
    }
  }

  RunOn(code, tree, exec_reason, ctx);
}

/**
 * @fn
 * @brief Run testcase without checking deplication
 * @param (tree) Tree of testcase
 * @param (exec_reason) Execution reason
 * @param (ctx) Context
 */
void NautilusState::RunOnWithoutDedup(const TreeLike& tree,
                                      ExecutionReason exec_reason,
                                      Context &ctx) {
  std::string code = tree.UnparseToVec(ctx);
  RunOn(code, tree, exec_reason, ctx);  
}

/**
 * @fn
 * @brief Run testcase
 * @param (code) String representation of testcase
 * @param (tree) Tree of testcase
 * @param (exec_reason) Execution reason
 * @param (ctx) Context
 */
void NautilusState::RunOn(std::string& code,
                          const TreeLike& tree_like,
                          ExecutionReason exec_reason,
                          Context &ctx) {
  u64 execution_time = ExecRaw(code);

  /* Get feedback */
  ExitStatusFeedback exit_status = executor->GetExitStatusFeedback();
  PersistentMemoryFeedback feedback
    = executor->GetAFLFeedback().ConvertToPersistent();

  // TODO: any way to avoid copy?
  const std::vector<uint8_t> old_bitmap(feedback.mem.get(),
                                        feedback.mem.get() + feedback.len);

  bool is_crash = exit_status.exit_reason == PUTExitReasonType::FAULT_CRASH;

  // TODO: remove this
  assert (old_bitmap.size() == bitmaps[is_crash].size());

  /* Get new bits */
  std::vector<size_t> new_bits;
  std::vector<uint8_t>& shared_bitmap = bitmaps[is_crash];

  for (size_t i = 0; i < old_bitmap.size(); i++) {
    if (old_bitmap[i] != 0 && shared_bitmap.at(i) == 0) {
      /* Newly set bit found */
      shared_bitmap[i] |= old_bitmap[i];
      new_bits.push_back(i);
    }
  }

  /* Check for non deterministic bits */
  if (new_bits.size()) {

    /* Only if not timeout */
    if (exit_status.exit_reason != PUTExitReasonType::FAULT_CRASH) {

      CheckForDeterministicBehavior(old_bitmap, new_bits, code);

      if (new_bits.size()) {
        Tree tree = tree_like.ToTree(ctx);
        queue.Add(std::move(tree),
                  std::move(old_bitmap),
                  exit_status.exit_reason,
                  ctx,
                  execution_time);
      }
    }

  }

  // TODO: run_on
  // exit_reason
  exec_reason = exec_reason;
}

/**
 * @fn
 * @brief Execute PUT with raw data as input
 * @param (code) Testcase
 * @return Execution time in nanoseconds
 */
u64 NautilusState::ExecRaw(const std::string& code) {
  using namespace std::chrono;

  system_clock::time_point start, end;
  const u8* data = reinterpret_cast<const u8*>(code.data());
  u32 size = code.size();

  if (u32 tmout = setting->exec_timeout_ms == 0) {
    /* Run without timeout */
    start = system_clock::now();
    executor->Run(data, size);
    end = system_clock::now();
  } else {
    /* Run with timeout*/
    start = system_clock::now();
    executor->Run(data, size, tmout);
    end = system_clock::now();
  }

  /* Calculate average execution */
  u64 execution_time = duration_cast<nanoseconds>(end - start).count();
  average_executions_per_sec = average_executions_per_sec * 0.9         \
    + ((1.0 / static_cast<double>(execution_time)) * 1000000000.0) * 0.1;

  return execution_time;
}

/**
 * @fn
 * @brief Update bits by checking deterministic behavior
 */
void NautilusState::CheckForDeterministicBehavior(
  const std::vector<uint8_t>& old_bitmap,
  std::vector<size_t>& new_bits,
  const std::string& code
) {
  for (size_t i = 0; i < 5; i++) {
    ExecRaw(code);
    InplaceMemoryFeedback new_feedback = executor->GetAFLFeedback();

    new_feedback.ShowMemoryToFunc(
      [&old_bitmap, &new_bits](const u8* run_bitmap, u32 len) {
        // TODO: remove this unnecessary loop
        for (size_t j = 0; j < len; j++) {
          if (run_bitmap[j] != old_bitmap.at(j)) {
            std::cout << "[-] Found fucky bit " << j << std::endl;
          }
        }

        /* Retain bits */
        for (ssize_t j = new_bits.size() - 1; j >= 0; j--) {
          if (run_bitmap[new_bits[j]] == 0) {
            new_bits.erase(new_bits.begin() + j);
          }
        }
      }
    );
  }
}

} // namespace fuzzuf::algorithm::nautilus::fuzzer
