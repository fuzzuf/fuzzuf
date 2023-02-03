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
 * @file create.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CREATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CREATE_HPP
#include <config.h>

#include "fuzzuf/algorithms/libfuzzer/exec_input_set_range.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow.hpp"
#include "fuzzuf/algorithms/libfuzzer/no_new_coverage.hpp"
#include "fuzzuf/algorithms/libfuzzer/select_seed.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * Build libFuzzer's mutator set using HierarFlow
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @param create_info Parameters on building the fuzzer
 * @return root node of the HierarFlow
 */
template <typename F, typename Ord>
auto createMutator(const FuzzerCreateInfo &create_info) {
  namespace hf = fuzzuf::hierarflow;

  dictionary::StaticDictionary manual_dictionary;
  Load(create_info.dictionaries, manual_dictionary, false,
       [](std::string &&m) { std::cerr << m << std::endl; });

  auto random = hf::CreateIrregularNode<standard_order::RandomCall<F, Ord>>();

  auto erase_bytes = hf::CreateNode<standard_order::EraseBytes<F, Ord>>();
  auto insert_byte_ = hf::CreateNode<standard_order::InsertByte<F, Ord>>();
  auto insert_repeated_bytes_ =
      hf::CreateNode<standard_order::InsertRepeatedBytes<F, Ord>>();
  auto change_byte_ = hf::CreateNode<standard_order::ChangeByte<F, Ord>>();
  auto change_bit_ = hf::CreateNode<standard_order::ChangeBit<F, Ord>>();
  auto shuffle_bytes_ = hf::CreateNode<standard_order::ShuffleBytes<F, Ord>>();
  auto change_ascii_integer_ =
      hf::CreateNode<standard_order::ChangeASCIIInteger<F, Ord>>();
  auto change_binary_integer_ =
      hf::CreateNode<standard_order::ChangeBinaryInteger<F, Ord>>();
  auto copy_part_ = hf::CreateNode<standard_order::CopyPart<F, Ord>>();

  auto crossover_ = hf::CreateNode<standard_order::Crossover<F, Ord>>();
  auto manual_dict = hf::CreateNode<
      standard_order::StaticDict<F, dictionary::StaticDictionary, Ord>>(
      std::move(manual_dictionary));
  auto persistent_auto_dict =
      hf::CreateNode<standard_order::DynamicDict<F, Ord>>();
  auto to_ascii_ = create_info.only_ascii
                       ? hf::CreateNode<standard_order::ToASCII<F, Ord>>()
                       : hf::CreateNode<Proxy<F>>();
  auto root = hf::CreateNode<Proxy<F>>();

  if (create_info.do_crossover) {
    root << (random <= (erase_bytes || insert_byte_ || insert_repeated_bytes_ ||
                        change_byte_ || change_bit_ || shuffle_bytes_ ||
                        change_ascii_integer_ || change_binary_integer_ ||
                        copy_part_ || crossover_ || manual_dict ||
                        persistent_auto_dict) ||
             to_ascii_);
  } else {
    root << (random <= (erase_bytes || insert_byte_ || insert_repeated_bytes_ ||
                        change_byte_ || change_bit_ || shuffle_bytes_ ||
                        change_ascii_integer_ || change_binary_integer_ ||
                        copy_part_ || manual_dict || persistent_auto_dict) ||
             to_ascii_);
  }

  return root;
}

/**
 * Build following flow using HierarFlow
 * * Execute target and retrive execution result
 * * Calculate features using execution result
 * * Add to corpus if the execution result is valuable
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @tparam Sink Type of the callable with one string argument
 * @param create_info Parameters on building the fuzzer
 * @param force_add_to_corpus If true, the execution result is added to the
 * corpus regardless of features. Otherwise, the execution result is added to
 * the corpus if the execution found novel features.
 * @param may_delete_file Set may_delete_file attribute to the execution result
 * ( This attribute is not used in current fuzzuf's implementation ).
 * @param persistent If true, the input is written to both memory and storage.
 * Otherwise, the input is stored on the memory only.
 * @param strict_match If true, the execution result with completely same unique
 * feature set to existing result causes REPLACE.
 * @param sink Callback function with one string argument to output messages.
 * @return root node of the HierarFlow
 */
template <typename F, typename Ord, typename Sink>
auto createExecuteAndFeedback(const FuzzerCreateInfo &create_info,
                              bool force_add_to_corpus, bool may_delete_file,
                              bool persistent, bool strict_match,
                              const Sink &sink) {
  namespace hf = fuzzuf::hierarflow;
  using fuzzuf::executor::LibFuzzerExecutorInterface;

  auto create_coverage = hf::CreateNode<Clear<F, decltype(Ord::coverage)>>();

  auto set_executor =
      hf::CreateNode<StaticAssign<F, decltype(Ord::executor_index)>>(
          create_info.target_offset);

  auto execute_ = hf::CreateNode<standard_order::Execute<F, Ord>>();

  auto collect_features =
      hf::CreateNode<standard_order::CollectFeatures<F, Ord>>();
  auto add_to_corpus = hf::CreateNode<standard_order::AddToCorpus<F, Ord>>(
      force_add_to_corpus, may_delete_file, persistent, strict_match,
      create_info.output_dir, Sink(sink));

  create_coverage << set_executor << execute_ << collect_features
                  << add_to_corpus;

  return create_coverage;
}

template <typename F, typename Ord, typename Sink>
auto createSymCC(const FuzzerCreateInfo &create_info, bool force_add_to_corpus,
                 bool may_delete_file, bool persistent, bool strict_match,
                 const Sink &sink) {
  namespace hf = fuzzuf::hierarflow;
  using fuzzuf::executor::LibFuzzerExecutorInterface;

  auto create_outputs = hf::CreateNode<Clear<F, decltype(Ord::symcc_out)>>();
  auto for_each_symcc_output = hf::CreateNode<
      ForEachDynamicData<F, decltype(Ord::symcc_out && Ord::input)>>();

  auto execute_ = hf::CreateNode<standard_order::ExecuteSymCC<F, Ord>>();

  create_outputs << execute_ << for_each_symcc_output
                 << createExecuteAndFeedback<F, Ord>(
                        create_info, force_add_to_corpus, may_delete_file,
                        persistent, strict_match, sink);

  return create_outputs;
}

/**
 * Build following flow using HierarFlow
 * For each initial inputs
 *   * Execute target and retrive execution result
 *   * Calculate features using execution result
 *   * Add to corpus
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @tparam Sink Type of the callable with one string argument
 * @param create_info Parameters on building the fuzzer
 * @param initial_inputs ExecInputSet that contains initial inputs
 * @param strict_match If true, the execution result with completely same unique
 * feature set to existing result causes REPLACE.
 * @param sink Callback function with one string argument to output messages.
 * @return root node of the HierarFlow
 */
template <typename F, typename Ord, typename Sink>
auto createInitialize(const FuzzerCreateInfo &create_info,
                      exec_input::ExecInputSet &initial_inputs,
                      bool strict_match, const Sink &sink) {
  namespace hf = fuzzuf::hierarflow;

  auto for_each_initial_input = hf::CreateNode<ForEachStaticData<
      F, ExecInputSetRange<true, ExecInputSetRangeInsertMode::NONE>,
      decltype(Ord::input)>>(
      initial_inputs |
      adaptor::exec_input_set_range<true, ExecInputSetRangeInsertMode::NONE>);

  auto update_distribution = hf::CreateNode<
      standard_order::UpdateDistribution<F, MakeVersion(12u, 0u, 0u), Ord>>(
      create_info.sparse_energy_updates, create_info.max_mutation_factor, sink);

  auto new_cov = hf::CreateNode<standard_order::IfNewCoverage<F, Ord>>();

  auto add_to_solution_ = hf::CreateNode<standard_order::AddToSolution<F, Ord>>(
      false, create_info.input_dir);

  auto nop3 = hf::CreateNode<Proxy<F>>();

  if (create_info.merge)
    nop3 << (for_each_initial_input << createExecuteAndFeedback<F, Ord>(
                 create_info, true, true, false, strict_match, sink) ||
             (new_cov << add_to_solution_) || update_distribution);
  else
    nop3 << (for_each_initial_input << createExecuteAndFeedback<F, Ord>(
                 create_info, true, true, false, strict_match, sink) ||
             update_distribution);

  return nop3;
}

/**
 * Build following flow using HierarFlow
 * * Select one input ( or two if crossover is enabled) and mutate it
 * * Execute target using generated input, calculate feature and add to corpus
 * if valuable
 * * Write input to storage if the execution crashed and added to corpus
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @tparam Sink Type of the callable with one string argument
 * @param target_path Path of the target executable
 * @param create_info Parameters on building the fuzzer
 * @param initial_inputs ExecInputSet that contains initial inputs
 * @param sink Callback function with one string argument to output messages.
 * @return root node of the HierarFlow
 */
template <typename F, typename Ord, typename Sink>
auto createRunone(const FuzzerCreateInfo &create_info,
                  exec_input::ExecInputSet & /*initial_inputs*/,
                  const Sink &sink) {
  namespace hf = fuzzuf::hierarflow;

  auto increment_counter =
      hf::CreateNode<StaticAppend<F, decltype(Ord::count)>>(1u);
  auto local_loop =
      hf::CreateNode<standard_order::RepeatUntilNewCoverage<F, Ord>>(
          create_info.max_mutation_retry_count);
  auto new_cov = hf::CreateNode<standard_order::IfNewCoverage<F, Ord>>();

  auto mutation_loop =
      hf::CreateNode<standard_order::RepeatUntilMutated<F, Ord>>(
          1, create_info.mutation_depth);

  auto random = hf::CreateNode<standard_order::RandomCall<F, Ord>>();

  auto select_input =
      hf::CreateNode<standard_order::ChooseRandomSeed<F, Ord>>(false);
  auto select_crossover = hf::CreateNode<
      ChooseRandomSeed<F, decltype(Ord::state && Ord::corpus && Ord::rng &&
                                   Ord::crossover && Ord::exec_result)>>(
      create_info.crossover_uniform_dist);

  auto update_dict = hf::CreateNode<standard_order::UpdateDictionary<F, Ord>>();

  auto increment_mutations_count_ =
      hf::CreateNode<standard_order::IncrementMutationsCount<F, Ord>>();

  auto create_dict_entry =
      hf::CreateNode<Clear<F, decltype(Ord::dict_history)>>();

  auto create_history =
      hf::CreateNode<Clear<F, decltype(Ord::mutation_history)>>();

  auto print =
      create_info.print_pcs
          ? hf::CreateNode<standard_order::PrintStatusForNewUnit<F, Ord>>(
                create_info.verbosity, create_info.max_mutations_to_print,
                create_info.max_unit_size_to_print, sink)
          : hf::CreateNode<Proxy<F>>();

  auto nop1 = hf::CreateNode<Proxy<F>>();

  auto nop2 = hf::CreateNode<Proxy<F>>();

  auto nop3 = hf::CreateNode<Proxy<F>>();

  auto add_to_solution = hf::CreateNode<standard_order::AddToSolution<F, Ord>>(
      create_info.crashed_only, create_info.output_dir);

  auto update_distribution = hf::CreateNode<
      standard_order::UpdateDistribution<F, MakeVersion(12u, 0u, 0u), Ord>>(
      create_info.sparse_energy_updates, create_info.max_mutation_factor, sink);

  auto nop4 = hf::CreateNode<Proxy<F>>();

  auto update_max_length =
      create_info.len_control
          ? hf::CreateNode<standard_order::UpdateMaxLength<F, Ord>>(
                create_info.max_input_length, create_info.len_control)
          : hf::CreateNode<Proxy<F>>();

  auto assign_last_corpus_update_run = hf::CreateNode<
      DynamicAssign<F, decltype(Ord::count && Ord::last_corpus_update_run)>>();

  namespace sp = utils::struct_path;
  auto symcc = hf::CreateNode<Proxy<F>>();
  if (create_info.symcc_target_count && create_info.symcc_freq) {
    if (create_info.symcc_freq >= 2u) {
      auto threshold = hf::CreateNode<If<
          F, decltype(sp::root / sp::ident<std::greater_equal<unsigned int>> &&
                      Ord::stuck_count && Ord::symcc_freq)>>();
      auto if_no_new_coverage =
          hf::CreateNode<If<F, decltype(sp::root / sp::ident<NoNewCoverage> &&
                                        Ord::state && Ord::exec_result)>>();
      auto if_new_coverage =
          hf::CreateNode<If<F, decltype(sp::root / sp::ident<NewCoverage> &&
                                        Ord::state && Ord::exec_result)>>();
      auto increment_stuck_count =
          hf::CreateNode<StaticAppend<F, decltype(Ord::stuck_count)>>(1u);
      auto reset_stuck_count1 =
          hf::CreateNode<StaticAssign<F, decltype(Ord::stuck_count)>>(0u);
      auto reset_stuck_count2 =
          hf::CreateNode<StaticAssign<F, decltype(Ord::stuck_count)>>(0u);

      symcc << (if_no_new_coverage
                    << (increment_stuck_count ||
                        threshold
                            << (reset_stuck_count1 ||
                                createSymCC<F, Ord>(create_info, false, true,
                                                    false, false, sink))) ||
                if_new_coverage << (reset_stuck_count2));
    } else {
      auto if_no_new_coverage =
          hf::CreateNode<If<F, decltype(sp::root / sp::ident<NoNewCoverage> &&
                                        Ord::state && Ord::exec_result)>>();
      symcc << (if_no_new_coverage << createSymCC<F, Ord>(
                    create_info, false, true, false, false, sink));
    }
  }

  nop4 << (select_crossover || select_input ||
           local_loop
               << (create_history || create_dict_entry ||
                   mutation_loop << createMutator<F, Ord>(create_info) ||
                   nop2 << (increment_mutations_count_ ||
                            createExecuteAndFeedback<F, Ord>(
                                create_info, false, true, false, false, sink) ||
                            new_cov
                                << (update_dict || add_to_solution || print ||
                                    assign_last_corpus_update_run)) ||
                   increment_counter) ||
           symcc || update_distribution || update_max_length);
  return nop4;
}

/**
 * Build all process of libFuzzer using HierarFlow
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @tparam Sink Type of the callable with one string argument
 * @param target_path Path of the target executable
 * @param create_info Parameters on building the fuzzer
 * @param initial_inputs ExecInputSet that contains initial inputs
 * @param sink Callback function with one string argument to output messages.
 * @return root node of the HierarFlow
 */
template <typename F, typename Ord, typename Sink>
auto create(const FuzzerCreateInfo &create_info,
            exec_input::ExecInputSet &initial_inputs, const Sink &sink) {
  namespace hf = fuzzuf::hierarflow;

  auto global_loop =
      hf::CreateNode<PartiallyDynamicRepeat<F, decltype(Ord::count)>>(
          create_info.total_cycles);

  auto nop1 = hf::CreateNode<Proxy<F>>();

  auto dump_state = create_info.print_final_stats
                        ? hf::CreateNode<StaticDump<F, decltype(Ord::state)>>(
                              "state\n", 1, "  ", sink)
                        : hf::CreateNode<Proxy<F>>();

  nop1 << (createInitialize<F, Ord>(create_info, initial_inputs, false, sink) ||
           global_loop << (createRunone<F, Ord>(create_info, initial_inputs,
                                                sink)) ||
           dump_state);

  return nop1;
}

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
