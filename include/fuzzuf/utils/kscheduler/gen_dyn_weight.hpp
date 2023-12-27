/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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
 * @file gen_dyn_weight.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_KSCHEDULER_GEN_DYN_WEIGHT_HPP
#define FUZZUF_INCLUDE_UTILS_KSCHEDULER_GEN_DYN_WEIGHT_HPP

#include <memory>
#include <boost/process.hpp>
#include <fuzzuf/utils/filesystem.hpp>

namespace fuzzuf::utils::kscheduler {

class GenDynWeight {
public:
  GenDynWeight(
    const fs::path &script_path,
    const fs::path &nk_path
  );
  ~GenDynWeight();
private:
  std::shared_ptr< boost::process::child > child;
};

}

#endif

