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
 * @file state.cpp
 * @brief Global state used during hieraflow loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/fuzzer/state.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/persistent_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer {

// MEMO: "this->" is used for members of Fuzzer in original Nautilus
NautilusState::NautilusState(
    std::shared_ptr<const NautilusSetting> setting,
    std::shared_ptr<executor::AFLExecutorInterface> executor)
    : setting(setting),
      executor(executor),
      cks(setting->path_to_workdir.string()),
      mutator(ctx),
      queue(setting->path_to_workdir.string()),
      execution_count(0),
      average_executions_per_sec(0),
      bits_found_by_havoc(0),
      bits_found_by_havoc_rec(0),
      bits_found_by_min(0),
      bits_found_by_min_rec(0),
      bits_found_by_splice(0),
      bits_found_by_det(0),
      bits_found_by_gen(0),
      asan_found_by_havoc(0),
      asan_found_by_havoc_rec(0),
      asan_found_by_min(0),
      asan_found_by_min_rec(0),
      asan_found_by_splice(0),
      asan_found_by_det(0),
      asan_found_by_gen(0),
      last_found_asan("Not found yet."),
      last_found_sig("Not found yet."),
      last_timeout("No timeout yet."),
      state_saved("State not saved yet."),
      total_found_asan(0),
      total_found_sig(0),
      total_found_hang(0),
      start_time(std::chrono::system_clock::now()),
      cycles_done(0) {
  bitmaps[false] = std::vector<uint8_t>(setting->bitmap_size, 0);
  bitmaps[true] = std::vector<uint8_t>(setting->bitmap_size, 0);
}

/**
 * @fn
 * @brief Run testcase after checking deplication
 * @param (tree) Tree of testcase
 * @param (exec_reason) Execution reason
 * @param (ctx) Context
 */
bool NautilusState::RunOnWithDedup(const TreeLike& tree,
                                   ExecutionReason exec_reason, Context& ctx) {
  std::string code = tree.UnparseToVec(ctx);

  /* Check if input is known */
  if (last_tried_inputs.find(code) != last_tried_inputs.end()) {
    return false;

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
  return true;
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
                                      Context& ctx) {
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
void NautilusState::RunOn(std::string& code, const TreeLike& tree_like,
                          ExecutionReason exec_reason, Context& ctx) {
  u64 execution_time = ExecRaw(code);

  /* Get feedback */
  feedback::ExitStatusFeedback exit_status = executor->GetExitStatusFeedback();
  feedback::PersistentMemoryFeedback feedback =
      executor->GetAFLFeedback().ConvertToPersistent();

  // TODO: any way to avoid copy?
  const std::vector<uint8_t> old_bitmap(feedback.mem.get(),
                                        feedback.mem.get() + feedback.len);

  bool is_crash =
      exit_status.exit_reason == feedback::PUTExitReasonType::FAULT_CRASH;

  /* Get new bits */
  std::vector<size_t> new_bits;
  // TODO: Use lock when multi-threaded
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
    if (exit_status.exit_reason != feedback::PUTExitReasonType::FAULT_CRASH) {
      CheckForDeterministicBehavior(old_bitmap, new_bits, code);

      if (new_bits.size()) {
        Tree tree = tree_like.ToTree(ctx);
        // TODO: Use lock when multi-threaded
        queue.Add(std::move(tree), std::move(old_bitmap),
                  exit_status.exit_reason, ctx, execution_time);
      }
    }
  }

  switch (exit_status.exit_reason) {
    case feedback::PUTExitReasonType::FAULT_NONE: { /* Normal exit */
      // TODO: Support ASAN (status=223) after executor is improved
      if (new_bits.size() == 0) break;

      /* Update bit count based on execution reason */
      switch (exec_reason) {
        case ExecutionReason::Havoc:
          this->bits_found_by_havoc++;
          break;
        case ExecutionReason::HavocRec:
          this->bits_found_by_havoc_rec++;
          break;
        case ExecutionReason::Min:
          this->bits_found_by_min++;
          break;
        case ExecutionReason::MinRec:
          this->bits_found_by_min_rec++;
          break;
        case ExecutionReason::Splice:
          this->bits_found_by_splice++;
          break;
        case ExecutionReason::Det:
          this->bits_found_by_det++;
          break;
        case ExecutionReason::Gen:
          this->bits_found_by_gen++;
          break;
      }
      break;
    }

    case feedback::PUTExitReasonType::FAULT_TMOUT: { /* Timeout */
      /* Get current datetime */
      const std::time_t t = std::time(nullptr);
      const std::tm* tm = std::localtime(&t);

      /* Update last timeout */
      std::ostringstream oss;
      oss << std::put_time(tm, "[%Y-%m-%d] %H:%M:%S");
      // TODO: Use lock when multi-threaded
      last_timeout = oss.str();
      total_found_hang++;

      /* Stringify tree */
      std::string buffer;
      tree_like.UnparseTo(ctx, buffer);

      /* Save tree to file */
      std::string filepath = fuzzuf::utils::StrPrintf(
          "%s/timeout/%09ld", setting->path_to_workdir.c_str(),
          execution_count);
      int fd = fuzzuf::utils::OpenFile(filepath, O_WRONLY | O_CREAT | O_TRUNC,
                                       S_IWUSR | S_IRUSR);  // 0600
      if (fd == -1) {
        /* Print testcase because we don't want to lose it */
        std::cout << buffer << std::endl;
        throw exceptions::unable_to_create_file(
            fuzzuf::utils::StrPrintf("Cannot save timeout: %s",
                                     filepath.c_str()),
            __FILE__, __LINE__);
      }
      fuzzuf::utils::WriteFile(fd, buffer.data(), buffer.size());
      fuzzuf::utils::CloseFile(fd);

      break;
    }

    case feedback::PUTExitReasonType::FAULT_CRASH: { /* Signal */
      if (new_bits.size() == 0) break;

      /* Get current datetime */
      const std::time_t t = std::time(nullptr);
      const std::tm* tm = std::localtime(&t);

      /* Update last sig */
      std::ostringstream oss;
      oss << std::put_time(tm, "[%Y-%m-%d] %H:%M:%S");
      // TODO: Use lock when multi-threaded
      total_found_sig++;
      // TODO: Use lock when multi-threaded
      last_found_sig = oss.str();

      /* Stringify tree */
      std::string buffer;
      tree_like.UnparseTo(ctx, buffer);

      /* Save tree to file */
      std::string filepath = fuzzuf::utils::StrPrintf(
          "%s/signaled/%d_%09ld", setting->path_to_workdir.c_str(),
          exit_status.signal, execution_count);
      int fd = fuzzuf::utils::OpenFile(filepath, O_WRONLY | O_CREAT | O_TRUNC,
                                       S_IWUSR | S_IRUSR);  // 0600
      if (fd == -1) {
        /* Print testcase because we don't want to lose it */
        std::cout << buffer << std::endl;
        throw exceptions::unable_to_create_file(
            fuzzuf::utils::StrPrintf("Cannot save crash: %s", filepath.c_str()),
            __FILE__, __LINE__);
      }
      fuzzuf::utils::WriteFile(fd, buffer.data(), buffer.size());
      fuzzuf::utils::CloseFile(fd);

      break;
    }

    default:  // pass
      break;
  }
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

  execution_count++;

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
  this->average_executions_per_sec =
      this->average_executions_per_sec * 0.9 +
      ((1.0 / static_cast<double>(execution_time)) * 1000000000.0) * 0.1;

  return execution_time;
}

/**
 * @fn
 * @brief Update bits by checking deterministic behavior
 */
void NautilusState::CheckForDeterministicBehavior(
    const std::vector<uint8_t>& old_bitmap, std::vector<size_t>& new_bits,
    const std::string& code) {
  for (size_t i = 0; i < 5; i++) {
    ExecRaw(code);
    feedback::InplaceMemoryFeedback new_feedback = executor->GetAFLFeedback();

    new_feedback.ShowMemoryToFunc(
        [&old_bitmap, &new_bits](const u8* run_bitmap, u32) {
          /* This loop looks unnecessary
          for (size_t j = 0; j < len; j++) {
            if (run_bitmap[j] != old_bitmap.at(j)) {
              std::cout << "[-] Found fucky bit " << j << std::endl;
            }
          }
          */

          /* Retain bits */
          for (ssize_t j = new_bits.size() - 1; j >= 0; j--) {
            if (run_bitmap[new_bits[j]] == 0) {
              new_bits.erase(new_bits.begin() + j);
            }
          }
        });
  }
}

bool NautilusState::HasBits(const TreeLike& tree,
                            std::unordered_set<size_t>& bits,
                            ExecutionReason exec_reason, Context& ctx) {
  RunOnWithoutDedup(tree, exec_reason, ctx);

  feedback::InplaceMemoryFeedback new_feedback = executor->GetAFLFeedback();

  bool found_all = true;
  new_feedback.ShowMemoryToFunc(
      [&bits, &found_all](const u8* run_bitmap, u32 len) {
        for (size_t bit : bits) {
          DEBUG_ASSERT(bit < len);
          UNUSED(len);

          if (run_bitmap[bit] == 0) {
            // TODO: handle edge counts properly
            found_all = false;
          }
        }
      });

  return found_all;
}

bool NautilusState::Minimize(QueueItem& input, size_t start_index,
                             size_t end_index) {
  FTester tester_min = [this](TreeMutation& t,
                              std::unordered_set<size_t>& fresh_bits,
                              Context& ctx) -> bool {
    return this->HasBits(t, fresh_bits, ExecutionReason::Min, ctx);
  };
  FTester tester_minrec = [this](TreeMutation& t,
                                 std::unordered_set<size_t>& fresh_bits,
                                 Context& ctx) -> bool {
    return this->HasBits(t, fresh_bits, ExecutionReason::MinRec, ctx);
  };

  bool min_simple = mutator.MinimizeTree(input.tree, input.fresh_bits, ctx,
                                         start_index, end_index, tester_min);
  bool min_rec = mutator.MinimizeRec(input.tree, input.fresh_bits, ctx,
                                     start_index, end_index, tester_minrec);

  if (min_simple && min_rec) {
    // TODO: Wait lock when threaded
    cks.AddTree(input.tree, ctx);

    input.recursions = input.tree.CalcRecursions(ctx);

    /* Stringify tree */
    std::string buffer;
    input.tree.UnparseTo(ctx, buffer);

    /* Save tree to file */
    std::string filepath = fuzzuf::utils::StrPrintf(
        "%s/queue/id:%09ld,er:%d.min", setting->path_to_workdir.c_str(),
        input.id, input.exit_reason);
    int fd = fuzzuf::utils::OpenFile(filepath, O_WRONLY | O_CREAT | O_TRUNC,
                                     S_IWUSR | S_IRUSR);  // 0600
    if (fd == -1) {
      throw exceptions::unable_to_create_file(
          fuzzuf::utils::StrPrintf("Cannot save tree: %s", filepath.c_str()),
          __FILE__, __LINE__);
    }
    fuzzuf::utils::WriteFile(fd, buffer.data(), buffer.size());
    fuzzuf::utils::CloseFile(fd);

    return true;
  }

  return false;
}

bool NautilusState::DeterministicTreeMutation(QueueItem& input,
                                              size_t start_index,
                                              size_t end_index) {
  FTesterMut tester = [this](TreeMutation& t, Context& ctx) -> bool {
    return this->RunOnWithDedup(t, ExecutionReason::Det, ctx);
  };

  bool done = mutator.MutRules(input.tree, ctx, start_index, end_index, tester);

  return done;
}

}  // namespace fuzzuf::algorithm::nautilus::fuzzer
