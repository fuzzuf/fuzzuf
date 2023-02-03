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
 * @file input_info.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"

#include "fuzzuf/algorithms/libfuzzer/exec_input_set_range.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/utils.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * Update energy of input value.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L74
 *
 * @param global_number_of_features Total number of known features
 * @param scale_per_exec_time If true, scale energy by variance of execution
 * time
 * @param average_unit_execution_time Average of execution time
 */
void InputInfo::updateEnergy(
    std::size_t global_number_of_features, bool scale_per_exec_time,
    std::chrono::microseconds average_unit_execution_time) {
  enabled = true;
  energy = 0.0;
  sum_incidence = 0.0;

  // Apply add-one smoothing to locally discovered features.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
  for (const auto &[id, incidence] : feature_freqs) {
#pragma GCC diagnostic pop
    double local_incidence = incidence + 1;
    energy -= local_incidence * std::log(local_incidence);
    sum_incidence += local_incidence;
  }

  // Apply add-one smoothing to locally undiscovered features.
  //   PreciseEnergy -= 0; // since log(1.0) == 0)
  sum_incidence += static_cast<double>(global_number_of_features) -
                   static_cast<double>(feature_freqs.size());

  // Add a single locally abundant feature apply add-one smoothing.
  const auto abd_incidence = static_cast<double>(executed_mutations_count + 1);
  energy -= abd_incidence * log(abd_incidence);
  sum_incidence += abd_incidence;

  // Normalize.
  if (sum_incidence != 0) {
    energy = energy / sum_incidence + std::log(sum_incidence);
  }

  if (scale_per_exec_time) {
    // Scaling to favor inputs with lower execution time.
    // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    uint32_t perf_score = 100;
    if (time_of_unit.count() > average_unit_execution_time.count() * 10) {
      perf_score = 10;
    } else if (time_of_unit.count() > average_unit_execution_time.count() * 4) {
      perf_score = 25;
    } else if (time_of_unit.count() > average_unit_execution_time.count() * 2) {
      perf_score = 50;
    } else if (time_of_unit.count() * 3 >
               average_unit_execution_time.count() * 4) {
      perf_score = 75;
    } else if (time_of_unit.count() * 4 < average_unit_execution_time.count()) {
      perf_score = 300;
    } else if (time_of_unit.count() * 3 < average_unit_execution_time.count()) {
      perf_score = 200;
    } else if (time_of_unit.count() * 2 < average_unit_execution_time.count()) {
      perf_score = 150;
    }
    // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    energy *= perf_score;
  }
}

/**
 * Delete feature Idx and its frequency from FeatureFreqs.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L51
 */
auto InputInfo::delete_feature_freq(std::uint32_t index) -> bool {
  if (feature_freqs.empty()) {
    return false;
  }

  // Binary search over local feature frequencies
  // sorted by index.
  auto lower =
      std::lower_bound(feature_freqs.begin(), feature_freqs.end(),
                       std::pair<std::uint32_t, std::uint16_t>(index, 0U));

  if (lower != feature_freqs.end() && lower->first == index) {
    feature_freqs.erase(lower);
    return true;
  }
  return false;
}

/**
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L122
 *
 */
void InputInfo::updateFeatureFrequency(std::uint32_t index) {
  needs_energy_update = true;
  // The local feature frequencies is an ordered vector of pairs.
  // If there are no local feature frequencies, push_back preserves order.
  // Set the feature frequency for feature Idx32 to 1.
  if (feature_freqs.empty()) {
    feature_freqs.emplace_back(index, 1U);
    return;
  }

  // Binary search over local feature frequencies sorted by index.
  const auto lower =
      std::lower_bound(feature_freqs.begin(), feature_freqs.end(),
                       std::pair<std::uint32_t, std::uint16_t>(index, 0U));

  // If feature Idx32 already exists, increment its frequency.
  // Otherwise, insert a new pair right after the next lower index.
  if (lower != feature_freqs.end() && lower->first == index) {
    lower->second++;
  } else {
    feature_freqs.insert(lower,
                         std::pair<std::uint32_t, std::uint16_t>(index, 1U));
  }
}

auto toString(std::string &dest, const InputInfo &value,
              std::size_t indent_count, const std::string &indent) -> bool {
  if (!value.enabled) {
    return true;
  }
  utils::make_indent(dest, indent_count, indent);
  dest += "InputInfo\n";
  ++indent_count;
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(id)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(time_of_unit)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(features_count)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(executed_mutations_count)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(never_reduce)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(may_delete_file)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(has_focus_function)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(reduced)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(needs_energy_update)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(energy)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(sum_incidence)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(unique_feature_set)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(feature_freqs)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(status)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(signal)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(weight)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(added_to_corpus)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(found_unique_features)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(sha1)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(input_size)
  return true;
}

auto toString(std::string &dest, const PartialCorpus &value,
              std::size_t indent_count, const std::string &indent) -> bool {
  utils::make_indent(dest, indent_count, indent);
  dest += "PartialCorpus\n";
  ++indent_count;
  for (const auto &v : value) {
    if (!toString(dest, v, indent_count, indent)) {
      std::cout << "oops" << std::endl;
      return false;
    }
  }
  return true;
}

auto toString(std::string &dest, const FullCorpus &value,
              std::size_t indent_count, const std::string &indent) -> bool {
  utils::make_indent(dest, indent_count, indent);
  dest += "FullCorpus\n";
  ++indent_count;
  if (!toString(dest, value.corpus, indent_count, indent)) {
    return false;
  }
  utils::make_indent(dest, indent_count, indent);
  dest += "data\n";
  ++indent_count;
  // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
  for (auto &data :
       const_cast<exec_input::ExecInputSet &>(value.inputs) |
           adaptor::exec_input_set_range<false,
                                         ExecInputSetRangeInsertMode::NONE>) {
    if (!utils::toStringADL(dest, data.GetID(), indent_count, indent)) {
      return false;
    }
    const bool empty = (data.GetLen() == 0U) || (data.GetBuf() == nullptr);
    if (empty) {
      data.LoadIfNotLoaded();
    }
    const bool still_empty =
        (data.GetLen() == 0U) || (data.GetBuf() == nullptr);
    if (still_empty) {
      dest += "(empty)";
      if (empty) {
        data.Unload();
      }
    } else if (!utils::toStringADL(
                   dest,
                   boost::make_iterator_range(
                       data.GetBuf(), std::next(data.GetBuf(), data.GetLen())),
                   indent_count + 1U, indent)) {
      if (empty) {
        data.Unload();
      }
      return false;
    }
    if (empty) {
      data.Unload();
    }
  }
  // NOLINTEND(cppcoreguidelines-pro-type-const-cast)
  return true;
}

}  // namespace fuzzuf::algorithm::libfuzzer
