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
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NEZHA_CREATE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NEZHA_CREATE_HPP
#include <config.h>

#include "fuzzuf/algorithms/libfuzzer/create.hpp"
#include "fuzzuf/algorithms/nezha/config.hpp"
#include "fuzzuf/algorithms/nezha/hierarflow.hpp"
#include "fuzzuf/algorithms/nezha/state.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"

namespace fuzzuf::algorithm::nezha {

/**
 * Build following flow using HierarFlow
 * * Execute specified target and retrive execution result
 * * Calculate features using execution result
 * * Add to corpus if the execution result is valuable
 * * Append value that represent whether the execution result was added to
 * corpus to traces
 * * Append hash value of standard output to outputs
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @tparam Sink Type of the callable with one string argument
 * @param create_info Parameters on building the fuzzer
 * @param use_output If true, standard output of the execution is treated as the
 * output of  execution. Otherwise, status code is treated as the output of
 * execution.
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
auto CreateRunSingleTarget(const FuzzerCreateInfo &create_info, bool use_output,
                           bool force_add_to_corpus, bool may_delete_file,
                           bool persistent, bool strict_match, size_t i,
                           const Sink &sink) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  using fuzzuf::executor::LibFuzzerExecutorInterface;
  auto create_local_coverage =
      hf::CreateNode<lf::Clear<F, decltype(Ord::coverage)>>();

  auto execute = hf::CreateNode<lf::standard_order::Execute<F, Ord>>();
  auto collect_features =
      hf::CreateNode<standard_order::CollectFeatures<F, Ord>>(
          i * (create_info.use_afl_coverage ? create_info.afl_shm_size
                                            : create_info.bb_shm_size));
  auto add_to_corpus = hf::CreateNode<lf::standard_order::AddToCorpus<F, Ord>>(
      force_add_to_corpus, may_delete_file, persistent, strict_match,
      create_info.output_dir, Sink(sink));
  auto new_cov = hf::CreateNode<lf::standard_order::IfNewCoverage<F, Ord>>();
  auto update_dict =
      hf::CreateNode<lf::standard_order::UpdateDictionary<F, Ord>>();
  auto print =
      create_info.print_pcs
          ? hf::CreateNode<lf::standard_order::PrintStatusForNewUnit<F, Ord>>(
                create_info.verbosity, create_info.max_mutations_to_print,
                create_info.max_unit_size_to_print, sink)
          : hf::CreateNode<lf::Proxy<F>>();

  auto nop1 = hf::CreateNode<lf::Proxy<F>>();

  auto nop2 = hf::CreateNode<lf::Proxy<F>>();

  auto gather_trace_ = hf::CreateNode<
      lf::DynamicAppend<F, decltype(Ord::added_to_corpus && Ord::trace)>>();

  auto gather_output_ =
      (use_output)
          ? hf::CreateNode<standard_order::GatherOutput<F, Ord>>()
          : hf::CreateNode<lf::DynamicAppend<F, decltype(Ord::single_status &&
                                                         Ord::status)>>();

  auto assign_last_corpus_update_run = hf::CreateNode<lf::DynamicAssign<
      F, decltype(Ord::count && Ord::last_corpus_update_run)>>();

  auto set_executor =
      hf::CreateNode<lf::StaticAssign<F, decltype(Ord::executor_index)>>(i);

  nop1 << (create_local_coverage << set_executor << execute << collect_features
                                 << add_to_corpus ||
           new_cov << (update_dict || print || assign_last_corpus_update_run) ||
           gather_trace_ << gather_output_);
  return nop1;
}

/**
 * Build following flow using HierarFlow
 * * For each target executables, run everything defined at
 * CreateRunSingleTarget
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @tparam Sink Type of the callable with one string argument
 * @param create_info Parameters on building the fuzzer
 * @param use_output If true, standard output of the execution is treated as the
 * output of  execution. Otherwise, status code is treated as the output of
 * execution.
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
auto CreateRunTargets(const FuzzerCreateInfo &create_info, bool use_output,
                      bool force_add_to_corpus, bool may_delete_file,
                      bool persistent, bool strict_match, const Sink &sink) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;
  auto nop1 = hf::CreateNode<lf::Proxy<F>>();

  auto run = hf::CreateNode<lf::Proxy<F>>();

  for (std::size_t i = create_info.target_offset;
       i != create_info.target_offset + create_info.target_count; ++i) {
    auto single = CreateRunSingleTarget<F, Ord>(
        create_info, use_output, force_add_to_corpus, may_delete_file,
        persistent, strict_match, i, sink);
    run << single;
  }

  return run;
}

/**
 * Build following flow using HierarFlow
 * * Select one input ( or two if crossover is enabled) and mutate it
 * * Run everything defined at CreateRunTargets using the input
 * * Append execution result to solutions if the traces or outputs is unique
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @tparam Sink Type of the callable with one string argument
 * @param create_info Parameters on building the fuzzer
 * @param use_output If true, standard output of the execution is treated as the
 * output of  execution. Otherwise, status code is treated as the output of
 * execution.
 * @param sink Callback function with one string argument to output messages.
 * @return root node of the HierarFlow
 */
template <typename F, typename Ord, typename Sink>
auto createRunone(const FuzzerCreateInfo &create_info, bool use_output,
                  const Sink &sink) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;

  auto increment_counter =
      hf::CreateNode<lf::StaticAppend<F, decltype(Ord::count)>>(1u);
  auto local_loop =
      hf::CreateNode<lf::standard_order::RepeatUntilNewCoverage<F, Ord>>(
          create_info.max_mutation_retry_count);

  auto mutation_loop =
      hf::CreateNode<lf::standard_order::RepeatUntilMutated<F, Ord>>(
          1, create_info.mutation_depth);

  auto select_input =
      hf::CreateNode<lf::standard_order::ChooseRandomSeed<F, Ord>>(false);
  auto select_crossover = hf::CreateNode<
      lf::ChooseRandomSeed<F, decltype(Ord::state && Ord::corpus && Ord::rng &&
                                       Ord::crossover && Ord::exec_result)>>(
      create_info.crossover_uniform_dist);

  auto update_dict =
      hf::CreateNode<lf::standard_order::UpdateDictionary<F, Ord>>();

  auto increment_mutations_count =
      hf::CreateNode<lf::standard_order::IncrementMutationsCount<F, Ord>>();

  auto create_dict_entry =
      hf::CreateNode<lf::Clear<F, decltype(Ord::dict_history)>>();

  auto create_history =
      hf::CreateNode<lf::Clear<F, decltype(Ord::mutation_history)>>();

  auto nop1 = hf::CreateNode<lf::Proxy<F>>();

  auto nop2 = hf::CreateNode<lf::Proxy<F>>();

  auto nop3 = hf::CreateNode<lf::Proxy<F>>();

  auto nop4 = hf::CreateNode<lf::Proxy<F>>();

  auto nop5 = hf::CreateNode<lf::Proxy<F>>();

  auto add_to_solution =
      use_output
          ? hf::CreateNode<standard_order::AddToSolution<F, Ord>>(
                create_info.output_dir)
          : hf::CreateNode<
                AddToSolution<F, decltype(Ord::input && Ord::exec_result &&
                                          Ord::trace && Ord::known_traces &&
                                          Ord::status && Ord::known_status)>>(
                create_info.output_dir);

  auto create_trace = hf::CreateNode<lf::Clear<F, decltype(Ord::trace)>>();
  auto create_outputs = hf::CreateNode<lf::Clear<F, decltype(Ord::outputs)>>();

  auto update_distribution =
      hf::CreateNode<lf::standard_order::UpdateDistribution<
          F, lf::MakeVersion(12u, 0u, 0u), Ord>>(
          create_info.sparse_energy_updates, create_info.max_mutation_factor,
          sink);

  auto update_max_length =
      create_info.len_control
          ? hf::CreateNode<lf::standard_order::UpdateMaxLength<F, Ord>>(
                create_info.max_input_length, create_info.len_control)
          : hf::CreateNode<lf::Proxy<F>>();

  /*
   * Due to current clang-format rule, following graph definition is formatted
   * in unexpected form. The rule need to be changed to preserve indentation of
   * graph definition.
   */
  nop4 << (select_crossover || select_input ||
           local_loop << (create_history || create_dict_entry ||
                          mutation_loop
                              << lf::createMutator<F, Ord>(create_info) ||
                          increment_mutations_count || create_outputs ||
                          create_trace ||
                          CreateRunTargets<F, Ord>(create_info, use_output,
                                                   false, true, false, true,
                                                   sink) ||
                          add_to_solution) ||
           increment_counter || update_distribution || update_max_length);
  return nop4;
}

/**
 * Build all process of Nezha using HierarFlow
 * @tparam F Input function type of HierarFlow node
 * @tparam Ord Type to specify how to retrive values from the arguments.
 * @tparam Sink Type of the callable with one string argument
 * @param create_info Parameters on building the fuzzer
 * @param initial_inputs ExecInputSet that contains initial inputs
 * @param sink Callback function with one string argument to output messages.
 * @return root node of the HierarFlow
 */
template <typename F, typename Ord, typename Sink>
auto create(const libfuzzer::FuzzerCreateInfo &create_info, bool use_output,
            exec_input::ExecInputSet &initial_inputs, const Sink &sink) {
  namespace lf = fuzzuf::algorithm::libfuzzer;
  namespace hf = fuzzuf::hierarflow;

  auto global_loop =
      hf::CreateNode<lf::PartiallyDynamicRepeat<F, decltype(Ord::count)>>(
          create_info.total_cycles);

  auto nop1 = hf::CreateNode<lf::Proxy<F>>();
  auto nop2 = hf::CreateNode<lf::Proxy<F>>();

  auto dump_state =
      create_info.print_final_stats
          ? hf::CreateNode<lf::StaticDump<F, decltype(Ord::state)>>(
                "state\n", 1, "  ", sink)
          : hf::CreateNode<lf::Proxy<F>>();

  nop1 << (lf::createInitialize<F, Ord>(create_info, initial_inputs, true,
                                        sink) ||
           global_loop << createRunone<F, Ord>(create_info, use_output, sink) ||
           dump_state);
  return nop1;
}
}  // namespace fuzzuf::algorithm::nezha
#endif
