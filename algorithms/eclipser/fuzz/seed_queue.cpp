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
 * @file seed_queue.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/seed_queue.hpp>

namespace fuzzuf::algorithm::eclipser::seed_queue {
void SeedQueue::EnqueueInplace( Priority priority, const seed::Seed &seed ) {
  if( priority == Priority::Favored ) {
    favoreds.push_back( seed );
  }
  else if( priority == Priority::Normal ) {
    normals.push_back( seed );
  }
}
void SeedQueue::EnqueueInplace( Priority priority, seed::Seed &&seed ) {
  if( priority == Priority::Favored ) {
    favoreds.push_back( std::move( seed ) );
  }
  else if( priority == Priority::Normal ) {
    normals.push_back( std::move( seed ) );
  }
}
std::pair< Priority, seed::Seed > SeedQueue::DequeueInplace() {
  if( favoreds.empty() ) {
    auto seed = normals.front();
    normals.pop_front();
    return std::make_pair( Priority::Normal, std::move( seed ) );
  }
  else {
    auto seed = favoreds.front();
    favoreds.pop_front();
    return std::make_pair( Priority::Normal, std::move( seed ) );
  }
}
void SeedQueue::to_json( nlohmann::json &dest ) const {
  dest = nlohmann::json::object();
  dest[ "favoreds" ] = nlohmann::json::array();
  for( const auto &v: favoreds ) {
    dest[ "favoreds" ].push_back( v );
  }
  dest[ "normals" ] = nlohmann::json::array();
  for( const auto &v: normals ) {
    dest[ "normals" ].push_back( v );
  }
}
void SeedQueue::from_json( const nlohmann::json &src ) {
  favoreds.clear();
  normals.clear();
  if( src.find( "normals" ) != src.end() ) {
    for( const auto &v: src[ "normals" ] ) {
      normals.push_back( v );
    }
  }
  if( src.find( "favoreds" ) != src.end() ) {
    for( const auto &v: src[ "favoreds" ] ) {
      favoreds.push_back( v );
    }
  }
}

void to_json( nlohmann::json &dest, const SeedQueue &src ) {
  src.to_json( dest );
}

void from_json( const nlohmann::json &src, SeedQueue &dest ) {
  dest.from_json( src );
}

}


