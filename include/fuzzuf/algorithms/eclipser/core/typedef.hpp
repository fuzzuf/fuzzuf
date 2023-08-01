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
 * @file typedef.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_TYPEDEF_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_TYPEDEF_HPP
#include <cstddef>
#include <variant>
#include <iostream>
#include <optional>
#include <config.h>
#ifdef HAS_NLOHMANN_JSON_FWD
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif
#include <boost/multiprecision/cpp_int.hpp>
#include "fuzzuf/algorithms/eclipser/core/config.hpp"

namespace fuzzuf::algorithm::eclipser {

enum class Direction {
  Stay,
  Left,
  Right
};

std::ostream &operator<<( std::ostream&, Direction );
std::string ToString( Direction src );
void to_json( nlohmann::json &dest, const Direction &src );
void from_json( const nlohmann::json &src, Direction &dest );

struct StdInput {};
struct FileInput {
  std::string filepath;
};

using InputSource = std::variant< StdInput, FileInput >;

void to_json( nlohmann::json &dest, const InputSource &src );
void from_json( const nlohmann::json &src, InputSource &dest );

enum class CoverageGain {
  NoGain,
  NewPath,
  NewEdge
};

void to_json( nlohmann::json &dest, const CoverageGain &src );
void from_json( const nlohmann::json &src, CoverageGain &dest );

enum class Tracer {
  Coverage,
  Branch,
  BBCount
};

std::string to_string( Tracer );
void to_json( nlohmann::json &dest, const Tracer &src );
void from_json( const nlohmann::json &src, Tracer &dest );


/// Priority of found seed. A seed that increased edge coverage is assigned
/// 'Favored' priority, while a seed that increased path coverage is assigned
/// 'Normal' priority.
enum class Priority {
  Favored,
  Normal
};

void to_json( nlohmann::json &dest, const Priority &src );
void from_json( const nlohmann::json &src, Priority &dest );

namespace priority {

std::optional< Priority > OfCoverageGain( CoverageGain v );

}

enum class Arch {
  X86,
  X64
};

void to_json( nlohmann::json &dest, const Arch &src );
void from_json( const nlohmann::json &src, Arch &dest );

enum class Signal {
  ERROR = -1,
  NORMAL = 0,
  SIGILL = 4,
  SIGABRT = 6,
  SIGFPE = 8,
  SIGSEGV = 11,
  SIGALRM = 14
};

void to_json( nlohmann::json &dest, const Signal &src );
void from_json( const nlohmann::json &src, Signal &dest );

enum class Signedness {
  Signed,
  Unsigned
};

void to_json( nlohmann::json &dest, const Signedness &src );
void from_json( const nlohmann::json &src, Signedness &dest );

enum class Sign {
  Positive,
  Negative,
  Zero
};

void to_json( nlohmann::json &dest, const Sign &src );
void from_json( const nlohmann::json &src, Sign &dest );

struct NonLinear {};
struct Unsolvable {};

enum class CoverageMeasure {
  Ignore = 1,
  NonCumulative = 2,
  Cumulative = 3
};
  
namespace signal {

bool IsCrash( Signal signal );
bool IsSegfault( Signal signal );
bool IsIllegal( Signal signal );
bool IsFPE( Signal signal );
bool IsAbort( Signal signal );
bool IsTimeout( Signal signal );

}

}



#endif

