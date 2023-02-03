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

#define BOOST_TEST_MODULE mutator.more_havoc
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#include <string>

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_setting.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_state.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/exec_input/on_memory_exec_input.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/mutator/mutator.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/utils/hex_dump.hpp"

// Mutator needs "Tag" which represents what algorithm is going to use Mutator.
// We just prepare a temporary Tag.
struct TestTag {};

// This class just returns a constant that is passed during construction.
// Instances of this class is used as mutop_optimizer in Havoc
// to test the probability distribution of selecting mutation operators
class ConstantMutopSelector : public fuzzuf::optimizer::Optimizer<u32> {
 public:
  ConstantMutopSelector(u32 ret) : ret(ret) {}
  u32 CalcValue() override { return ret; }

 private:
  u32 ret;
};

// Check if Mutator::Havoc crashes or causes any access violations.
// At the same time, this test makes sure that all the switch cases
// beyond mutator::NUM_CASE are implemented without omissions in Havoc.
BOOST_AUTO_TEST_CASE(MutatorMoreHavoc) {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_STANDARD_TEST_DIRS

  // We prepare (AFLPLUSPLUS_NUM_CASE - mutator::NUM_CASE) number of
  // distributions. The i-th distribution always returns i. That is, chances of
  // the integer i being returned are 100%. Using these distributions, we can
  // check if each switch case is really implemented, and doesn't crash.

  // The seed can be anything, but it should be long to some extent
  // and all its bytes should be different.
  std::vector<u8> seed(100);
  std::iota(seed.begin(), seed.end(), 1);

  // Also, extras and a_extras can be anything, but they should have at least
  // one element.
  using fuzzuf::algorithm::afl::dictionary::AFLDictData;
  std::vector<AFLDictData> extras(1, AFLDictData({100, 101, 102, 103}));
  std::vector<AFLDictData> a_extras(1, AFLDictData({'H', 'e', 'l', 'l', 'o'}));

  fuzzuf::exec_input::ExecInputSet
      input_set;  // to create OnMemoryInputSet, we need the set(factory)

  // The following objects are just dummy to create AFLplusplusState
  using fuzzuf::algorithm::aflplusplus::AFLplusplusSetting;
  using fuzzuf::executor::AFLExecutorInterface;
  using fuzzuf::executor::NativeLinuxExecutor;
  std::vector<std::string> argv{"non-existent-program", "someargument"};
  auto setting = std::make_shared<AFLplusplusSetting>(
      argv, input_dir.string(), output_dir.string(), 1000, 0, false, false,
      fuzzuf::utils::CPUID_BIND_WHICHEVER,
      fuzzuf::algorithm::aflfast::option::FAST, "test");
  auto native_executor = std::make_shared<NativeLinuxExecutor>(
      argv, 1000, 0, false, "non-existent-file", 0, 0);
  auto executor =
      std::make_shared<AFLExecutorInterface>(std::move(native_executor));

  std::cout
      << "Going to check mutations provided by AFLplusplus custom cases..."
      << std::endl;
  namespace pph = fuzzuf::algorithm::aflplusplus::havoc;
  for (u32 i = pph::AFLPLUSPLUS_ADDBYTE; i < pph::AFLPLUSPLUS_NUM_CASE; i++) {
    std::cout << "check the " << i << "-th mutation." << std::endl;

    // Create an instance of Mutator.
    auto input = input_set.CreateOnMemory(&seed[0], seed.size());
    auto mutator = fuzzuf::mutator::Mutator<TestTag>(*input);

    // Create the i-th distribution.
    auto case_dist = ConstantMutopSelector(i);
    std::unique_ptr<fuzzuf::optimizer::HavocOptimizer> havoc_optimizer(
        new fuzzuf::optimizer::ConstantBatchHavocOptimizer(1024, case_dist));

    using fuzzuf::algorithm::aflplusplus::AFLplusplusState;
    AFLplusplusState state(setting, executor, std::move(havoc_optimizer));

    // valid seeds are needed for AFLPLUSPLUS_SPLICE_OVERWRITE and
    // AFLPLUSPLUS_SPLICE_INSERT
    state.AddToQueue("dummy_file1", (const u8*)"ABC", 3, true);
    state.AddToQueue("dummy_file2", (const u8*)"XYZ", 3, true);

    mutator.Havoc(extras, a_extras, *state.havoc_optimizer,
                  pph::AFLplusplusCustomCases<AFLplusplusState>(state));

    // Make sure that Havoc actually modified the input.
    std::vector<u8> modified_seed(mutator.GetBuf(),
                                  mutator.GetBuf() + mutator.GetLen());
    BOOST_CHECK(seed != modified_seed);
  }

  // Make sure that Havoc passes through the default case
  // when a distribution return an integer other than 0, 1, ..., NUM_CASE-1
  auto input = input_set.CreateOnMemory(&seed[0], seed.size());
  auto mutator = fuzzuf::mutator::Mutator<TestTag>(*input);

  // Create a distribution that always returns NUM_CASE.
  auto case_dist = ConstantMutopSelector(pph::AFLPLUSPLUS_NUM_CASE);
  auto havoc_optimizer =
      fuzzuf::optimizer::ConstantBatchHavocOptimizer(1, case_dist);

  bool passed_custom_cases = false;
  auto custom_cases = [&passed_custom_cases](u32 r, u8*&, u32&,
                                             const std::vector<AFLDictData>&,
                                             const std::vector<AFLDictData>&) {
    // AFLplusplus's mutations always fall into custom cases.
    // If r >= AFLPLUSPLUS_NUM_CASE, then it will jump to the default case as
    // expected.
    if (r >= pph::AFLPLUSPLUS_NUM_CASE) passed_custom_cases = true;
  };
  mutator.Havoc(extras, a_extras, havoc_optimizer, custom_cases);

  BOOST_CHECK(passed_custom_cases);

  // Because custom_cases does nothing this time, the input cannot be modified.
  std::vector<u8> modified_seed(mutator.GetBuf(),
                                mutator.GetBuf() + mutator.GetLen());
  BOOST_CHECK(seed == modified_seed);
}
