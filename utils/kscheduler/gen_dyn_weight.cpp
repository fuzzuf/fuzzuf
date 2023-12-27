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

#include <fuzzuf/utils/kscheduler/gen_dyn_weight.hpp>

namespace fuzzuf::utils::kscheduler {

GenDynWeight::GenDynWeight(
  const fs::path &script_path,
  const fs::path &nk_path
) {
  auto env = boost::this_process::environment();
  env[ "PYTHONPATH" ] = nk_path.c_str();
  child.reset( new boost::process::child(
    boost::process::search_path( "python3" ),
    script_path.c_str(),
    env
  ) );
}

GenDynWeight::~GenDynWeight() {
  child->terminate();
  child.reset();
}

}

