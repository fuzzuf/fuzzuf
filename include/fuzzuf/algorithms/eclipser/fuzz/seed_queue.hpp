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
 * @file solve.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_FUZZ_SEED_QUEUE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_FUZZ_SEED_QUEUE_HPP

#include <deque>
#include <nlohmann/json_fwd.hpp>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>
#include <fuzzuf/algorithms/eclipser/core/seed.hpp>

namespace fuzzuf::algorithm::eclipser::seed_queue {

class SeedQueue {
public:
  bool IsEmpty() const {
    return favoreds.empty() && normals.empty();
  }
  void EnqueueInplace( Priority priority, const seed::Seed &seed );
  std::pair< Priority, seed::Seed > DequeueInplace();
  void to_json( nlohmann::json& ) const;
  void from_json( const nlohmann::json& );
private:
  std::deque< seed::Seed > favoreds;
  std::deque< seed::Seed > normals;
};
void to_json( nlohmann::json &dest, const SeedQueue &src );
void from_json( const nlohmann::json &src, SeedQueue &dest );

}

#endif

