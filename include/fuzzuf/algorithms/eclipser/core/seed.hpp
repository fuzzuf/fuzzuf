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
 * @file seed.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_SEED_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_ECLIPSER_CORE_SEED_HPP
#include <cstddef>
#include <random>
#include <vector>
#include <optional>
#include <config.h>
#ifdef HAS_NLOHMANN_JSON_FWD
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif
#include <fuzzuf/algorithms/eclipser/core/byte_val.hpp>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>

namespace fuzzuf::algorithm::eclipser::seed {

struct Seed {
  Seed();
  explicit Seed( const InputSource &source_ );
  Seed( const InputSource &source_, const std::vector< std::byte > &bytes );
  std::vector< std::byte > Concretize() const;
  const byteval::ByteVal &GetCurByteVal() const;
  std::size_t GetCurLength() const;
  std::size_t GetUnfixedByteIndex() const;
  Direction GetByteCursorDir() const;
  std::byte GetConcreteByteAt( std::size_t pos ) const;
  std::byte GetConcreteByteAt() const;
  std::vector< std::byte > GetConcreteBytesFrom( std::size_t pos, std::size_t len ) const;
  bool HasUnfixedByte() const;
  bool IsUnfixedByteAt( std::size_t offset ) const;
  bool IsUnfixedByteAt() const;
  std::size_t QueryLenToward( Direction direction_ ) const;
private:
  static std::size_t QueryUpdateBoundLeft( const byteval::ByteVals &byte_vals_, std::size_t byte_cursor );
  static std::size_t QueryUpdateBoundRight( const byteval::ByteVals &byte_vals_, std::size_t byte_cursor );
public:
  std::size_t QueryUpdateBound( Direction direction_ ) const;
  std::size_t QueryUpdateBound() const;
  std::vector< std::byte > QueryNeighborBytes( Direction direction_ ) const;
  std::vector< std::byte > QueryNeighborBytes() const;
  Seed &ConstrainByteAtInplace( Direction direction_, std::size_t offset, std::byte low, std::byte upper );
  Seed ConstrainByteAt( Direction direction_, std::size_t offset, std::byte low, std::byte upper ) const;
  Seed &ConstrainByteAtInplace( std::size_t offset, std::byte low, std::byte upper );
  Seed ConstrainByteAt( std::size_t offset, std::byte low, std::byte upper ) const;
  Seed &FixCurBytesInplace( Direction direction_, const std::vector< std::byte > &bytes );
  Seed FixCurBytes( Direction direction_, const std::vector< std::byte > &bytes ) const;
  Seed &FixCurBytesInplace( const std::vector< std::byte > &bytes );
  Seed FixCurBytes( const std::vector< std::byte > &bytes ) const;
  Seed &UpdateCurByteInplace( const byteval::ByteVal byte_val );
  Seed UpdateCurByte( const byteval::ByteVal byte_val ) const;
  Seed &SetCursorPosInplace( std::size_t new_pos );
  Seed SetCursorPos( std::size_t new_pos ) const;
  Seed &SetCursorDirInplace( Direction dir );
  Seed SetCursorDir( Direction dir ) const;
  bool StepCursorInplace();
  std::optional< Seed > StepCursor() const;
private:
  static std::int64_t FindUnfixedByte( const byteval::ByteVals &bytes, std::size_t cur_index );
  static std::int64_t FindUnfixedByteBackward( const byteval::ByteVals &bytes, std::size_t cur_index );
  bool MoveToUnfixedByteInplace();
  std::optional< Seed > MoveToUnfixedByte() const;
public:
  bool ProceedCursorInplace();
  std::optional< Seed > ProceedCursor() const;
  Seed &SetByteCursorDirInplace( Direction dir );
  Seed SetByteCursorDir( Direction dir ) const;
  template< typename R >
  Seed &ShuffleByteCursorInplace( R &rng ) {
    const auto new_byte_cursor = std::uniform_int_distribution( std::size_t( 0 ), byte_vals.size() - 1u )( rng );
    const auto new_cursor_dir = ( new_byte_cursor > ( byte_vals.size() / 2u) ) ? Direction::Left : Direction::Right;
    cursor_pos = new_byte_cursor;
    cursor_dir = new_cursor_dir;
    return *this;
  }
  template< typename R >
  Seed ShuffleByteCursor( R &rng ) const {
    auto new_seed = *this;
    new_seed.ShuffleByteCursorInplace( rng );
    return new_seed;
  }
  std::vector< Seed > RelocateCursor() const;  
  std::string ToString() const;
  byteval::ByteVals byte_vals;
  std::size_t cursor_pos = 0u;
  Direction cursor_dir = Direction::Right;
  InputSource source = StdInput();
};

/*
  // Auxiliary function for byteValsToStr() that handles 'Untouched' ByteVals.
  let private untouchedToStr untouchedList =
    if List.isEmpty untouchedList then ""
    elif List.length untouchedList < 4 then
      " " + String.concat " " (List.map ByteVal.toString untouchedList)
    else sprintf " ...%dbytes..." (List.length untouchedList)

  // Stringfy ByteVal list.
  let rec private byteValsToStr accumUntouched accumStrs byteVals =
    match byteVals with
    | [] -> accumStrs + untouchedToStr (List.rev accumUntouched)
    | headByteVal :: tailByteVals ->
      (match headByteVal with
      | Untouched _ -> // Just accumulate to 'accumUntouched' and continue
        byteValsToStr (headByteVal :: accumUntouched) accumStrs tailByteVals
      | Undecided _ | Fixed _ | Interval _ | Sampled _ ->
        let untouchedStr = untouchedToStr (List.rev accumUntouched)
        let byteValStr = ByteVal.toString headByteVal
        let accumStrs = accumStrs + untouchedStr + " " + byteValStr
        byteValsToStr [] accumStrs tailByteVals) // reset accumUntouched to []

  // Auxiliary function for byteValsToStr() that handles 'Untouched' ByteVals.
  let private untouchedToStr untouchedList =
    if List.isEmpty untouchedList then ""
    elif List.length untouchedList < 4 then
      " " + String.concat " " (List.map ByteVal.toString untouchedList)
    else sprintf " ...%dbytes..." (List.length untouchedList)

  // Stringfy ByteVal list.
  let rec private byteValsToStr accumUntouched accumStrs byteVals =
    match byteVals with
    | [] -> accumStrs + untouchedToStr (List.rev accumUntouched)
    | headByteVal :: tailByteVals ->
      (match headByteVal with
      | Untouched _ -> // Just accumulate to 'accumUntouched' and continue
        byteValsToStr (headByteVal :: accumUntouched) accumStrs tailByteVals
      | Undecided _ | Fixed _ | Interval _ | Sampled _ ->
        let untouchedStr = untouchedToStr (List.rev accumUntouched)
        let byteValStr = ByteVal.toString headByteVal
        let accumStrs = accumStrs + untouchedStr + " " + byteValStr
        byteValsToStr [] accumStrs tailByteVals) // reset accumUntouched to []

*/
void to_json( nlohmann::json &dest, const Seed &src );
void from_json( const nlohmann::json &src, Seed &dest );

}

#endif

