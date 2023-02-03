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
 * @file setting.hpp
 * @brief Setting of nautilus
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_SETTING_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_SETTING_HPP

#include <optional>
#include <string>
#include <vector>

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer {

struct NautilusSetting {
  NautilusSetting(std::vector<std::string>& args, std::string& path_to_grammar,
                  std::string& path_to_workdir, u32 exec_timeout_ms,
                  u64 exec_memlimit, bool forksrv, int cpuid_to_bind,

                  u8 number_of_threads, u64 thread_size,
                  u16 number_of_generate_inputs,
                  u64 number_of_deterministic_mutations, u64 max_tree_size,
                  u64 bitmap_size)
      : args(args),
        path_to_grammar(path_to_grammar),
        path_to_workdir(path_to_workdir),
        exec_timeout_ms(exec_timeout_ms),
        exec_memlimit(exec_memlimit),
        forksrv(forksrv),
        cpuid_to_bind(cpuid_to_bind),

        number_of_threads(number_of_threads),
        thread_size(thread_size),
        number_of_generate_inputs(number_of_generate_inputs),
        number_of_deterministic_mutations(number_of_deterministic_mutations),
        max_tree_size(max_tree_size),
        bitmap_size(bitmap_size) {
    fs::path target(args.at(0));
    banner_filename = target.filename().string();

    if (banner_filename.size() > 24) {
      banner_filename.resize(24);
      banner_filename += "...";
    }
  }

  std::string banner_filename;
  const std::vector<std::string>& args;
  const fs::path path_to_grammar;
  const fs::path path_to_workdir;
  u32 exec_timeout_ms;
  u64 exec_memlimit;

  bool forksrv;
  int cpuid_to_bind;

  u8 number_of_threads;
  u64 thread_size;
  u16 number_of_generate_inputs;
  u64 number_of_deterministic_mutations;
  u64 max_tree_size;
  u64 bitmap_size;
};

}  // namespace fuzzuf::algorithm::nautilus::fuzzer

#endif
