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
#ifndef FUZZUF_INCLUDE_ALGORITHM_AFL_SYMCC_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_AFL_SYMCC_FUZZER_HPP

#include <array>
#include <memory>
#include <unordered_set>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/cli/fuzzer/afl_symcc/build_from_args.hpp"
#include "fuzzuf/executor/afl_symcc_executor_interface.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/map_file.hpp"

namespace fuzzuf::algorithm::afl_symcc {

/**
 * @class AFLFuzzerTemplate
 * @brief Wrapper to afl::AFLFuzzerTemplate. This class append two member
 * functions required to run SymCC.
 * @tparam State AFL state type. The type is passed to afl::AFLFuzzerTemplate
 * straightforward.
 */
template <typename State>
struct AFLFuzzerTemplate final : public afl::AFLFuzzerTemplate<State> {
  /**
   * All constructor arguments are forwarded to afl::AFLFuzzerTemplate
   */
  explicit AFLFuzzerTemplate(std::unique_ptr<State> &&state)
      : afl::AFLFuzzerTemplate<State>(std::move(state)),
        fuzz_loop(
            afl::BuildAFLFuzzLoop(*afl::AFLFuzzerTemplate<State>::state)) {}
  virtual void OneLoop(void) override { fuzz_loop(); }

  /**
   * Add the input value to case_queue.
   * @param buf pointer to the input value
   * @param len length of the input value
   * @return inserted value in Testcase
   */
  auto AddToQueue(const unsigned char *buf, std::uint32_t len) const {
    const auto fn = fuzzuf::utils::StrPrintf(
        "%s/queue/id:%06u,op:symcc",
        afl::AFLFuzzerTemplate<State>::state->setting->out_dir.c_str(),
        afl::AFLFuzzerTemplate<State>::state->queued_paths);
    return afl::AFLFuzzerTemplate<State>::state->AddToQueue(fn, buf, len,
                                                            false);
  }
  /**
   * Get input value that AFL recently used.
   * @return input value
   */
  auto GetInput() const {
    const auto fn =
        afl::AFLFuzzerTemplate<State>::state
            ->case_queue
                [(afl::AFLFuzzerTemplate<State>::state->current_entry +
                  afl::AFLFuzzerTemplate<State>::state->case_queue.size() -
                  1u) %
                 afl::AFLFuzzerTemplate<State>::state->case_queue.size()]
            ->input->GetPath();
    return utils::map_file(fs::absolute(fs::path(fn)).string(), O_RDONLY, true);
  }
  State &GetState() const { return *afl::AFLFuzzerTemplate<State>::state; }

 private:
  hierarflow::HierarFlowNode<void(void), void(void)> fuzz_loop;
};

/**
 * @class AFLSymCCFuzzerTemplate
 * @brief The fuzzer executes AFL and SymCC alternately.
 * @tparam State AFL state type. The type is passed to afl::AFLFuzzerTemplate
 * straightforward.
 */
template <typename State>
class AFLSymCCFuzzerTemplate : public fuzzer::Fuzzer {
 public:
  /**
   * @param afl_ AFL fuzzer instance
   * @param options_ SymCC parameters
   * @param executor_ Executor to run target compiled by SymCC
   */
  AFLSymCCFuzzerTemplate(
      std::unique_ptr<AFLFuzzerTemplate<State>> &&afl_,
      fuzzuf::cli::fuzzer::afl_symcc::SymCCOptions &&options_,
      std::shared_ptr<fuzzuf::executor::AFLSymCCExecutorInterface> &&executor_)
      : afl(std::move(afl_)),
        cycle(0u),
        options(std::move(options_)),
        executor(std::move(executor_)) {}
  /**
   * Call AFLFuzzerTemplate::OneLoop(), then execute SymCC.
   */
  virtual void OneLoop() = 0;
  /**
   * Call AFLFuzzerTemplate::ReceiveStopSignal()
   */
  virtual void ReceiveStopSignal() { afl->ReceiveStopSignal(); }
  /**
   * Call AFLFuzzerTemplate::ShouldEnd()
   */
  virtual bool ShouldEnd() { return afl->ShouldEnd(); }

 protected:
  /**
   * Execute SymCC
   */
  std::unique_ptr<AFLFuzzerTemplate<State>> afl;
  std::size_t cycle;
  fuzzuf::cli::fuzzer::afl_symcc::SymCCOptions options;
  std::shared_ptr<fuzzuf::executor::AFLSymCCExecutorInterface> executor;
  std::unordered_set<std::string> existing;
};

class AFLSymCCFuzzer final : public AFLSymCCFuzzerTemplate<afl::AFLState> {
 public:
  using AFLSymCCFuzzerTemplate<afl::AFLState>::AFLSymCCFuzzerTemplate;
  virtual void OneLoop(void) override;

 private:
  void SyncFuzzers();
  void RunSymCC();
};

}  // namespace fuzzuf::algorithm::afl_symcc

#endif
