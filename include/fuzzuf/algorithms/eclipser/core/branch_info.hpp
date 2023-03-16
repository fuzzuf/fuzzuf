/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file branch_info.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_BRANCH_INFO_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_BRANCH_INFO_HPP
#include <cstddef>
#include <nlohmann/json_fwd.hpp>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>
#include <fuzzuf/algorithms/eclipser/core/bigint.hpp>

namespace fuzzuf::algorithm::eclipser {

enum class CompareType {
  Equality,
  SignedSize,
  UnsignedSize
};

void to_json( nlohmann::json &dest, const CompareType &src );
void from_json( const nlohmann::json &src, CompareType &dest );

struct BranchPoint {
  std::uint64_t addr = 0u;
  int idx = 0;
};

void to_json( nlohmann::json &dest, const BranchPoint &src );
void from_json( const nlohmann::json &src, BranchPoint &dest );

struct Context {
  std::vector< std::byte > bytes;
  Direction byte_dir = Direction::Right;
};

struct BranchInfo {
  std::uint64_t inst_addr = 0u;
  CompareType branch_type = CompareType::Equality;
  BigInt try_value = 0;
  unsigned int operand_size = 0u;
  std::uint64_t operand1 = 0u;
  std::uint64_t operand2 = 0u;
  BigInt distance = 0;
};

void to_json( nlohmann::json &dest, const BranchInfo &src );
void from_json( const nlohmann::json &src, BranchInfo &dest );

using BranchTrace = std::vector< BranchInfo >;
using BranchTraces = std::unordered_map< std::uint64_t, BranchTrace >;

namespace branch_info {

BigInt InterpretAs(
  Signedness sign,
  std::size_t size,
  std::uint64_t x
);

}

}

#endif

