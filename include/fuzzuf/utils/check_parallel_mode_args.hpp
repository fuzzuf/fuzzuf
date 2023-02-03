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
 * @file check_parallel_mode_args.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_CHECK_PARALLEL_MODE_ARGS_HPP
#define FUZZUF_INCLUDE_UTILS_CHECK_PARALLEL_MODE_ARGS_HPP

#include <boost/program_options.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/filesystem.hpp>
#include <fuzzuf/utils/parallel_mode.hpp>
#include <iostream>

namespace fuzzuf::utils {

template <typename T, typename U>
void CheckParallelModeArgs(const boost::program_options::variables_map &vm,
                           T &afl_options, U &global_options) {
  if (vm.count("parallel-deterministic") && vm.count("parallel-random")) {
    std::cout << "-M and -S cannot be used at the same time" << std::endl;
    throw exceptions::invalid_argument("The path doesn't exist", __FILE__,
                                       __LINE__);
  } else if (vm.count("parallel-deterministic")) {
    afl_options.parallel_mode = utils::ParallelModeT::DETERMINISTIC;
    const auto instance_path = fs::path(afl_options.instance_id);
    if (instance_path != instance_path.filename() ||
        instance_path == fs::path(".") || instance_path == fs::path("..") ||
        (fs::exists(instance_path) && !fs::is_directory(instance_path))) {
      std::cout << "Invalid instance ID : " << afl_options.instance_id
                << std::endl;
      throw exceptions::invalid_argument("The path doesn't exist", __FILE__,
                                         __LINE__);
    }
    global_options.out_dir =
        (fs::path(global_options.out_dir) / instance_path).string();
  } else if (vm.count("parallel-random")) {
    afl_options.parallel_mode = utils::ParallelModeT::RANDOM;
    const auto instance_path = fs::path(afl_options.instance_id);
    if (instance_path != instance_path.filename() ||
        instance_path == fs::path(".") || instance_path == fs::path("..") ||
        (fs::exists(instance_path) && !fs::is_directory(instance_path))) {
      std::cout << "Invalid instance ID : " << afl_options.instance_id
                << std::endl;
      throw exceptions::invalid_argument("The path doesn't exist", __FILE__,
                                         __LINE__);
    }
    global_options.out_dir =
        (fs::path(global_options.out_dir) / instance_path).string();
  }
}

}  // namespace fuzzuf::utils

#endif
