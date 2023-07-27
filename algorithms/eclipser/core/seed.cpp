#include <cstddef>
#include <variant>
#include <type_traits>
#include <boost/range/iterator_range.hpp>
#include <nlohmann/json.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>
#include <fuzzuf/algorithms/eclipser/core/seed.hpp>
#include <fuzzuf/utils/type_traits/remove_cvr.hpp>

namespace fuzzuf::algorithm::eclipser::seed {

Seed::Seed() {}
Seed::Seed( const InputSource &source_ ) : source( source_ ) {
  byte_vals = std::visit(
    []( const auto &v ) {
      byteval::ByteVals bytes;
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, StdInput > ) {
        bytes.resize( INIT_INPUT_LEN, byteval::NewByteVal( std::byte( 'A' ) ) );
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, FileInput > ) {
        bytes.resize( INIT_INPUT_LEN, byteval::NewByteVal( std::byte( 0 ) ) );
      }
      return bytes;
    },
    source
  );
}
Seed::Seed( const InputSource &source_, const std::vector< std::byte > &bytes ) :
  source( source_ ) {
  // Do not allow empty content.
  if( bytes.empty() ) {
    throw exceptions::invalid_argument( "Seed.makeWith() with empty bytes", __FILE__, __LINE__ );
  }
  std::transform(
    bytes.begin(), bytes.end(), std::back_inserter( byte_vals ),
    byteval::NewByteVal
  );
}
std::vector< std::byte > Seed::Concretize() const {
  std::vector< std::byte > temp;
  std::transform(
    byte_vals.begin(), byte_vals.end(), std::back_inserter( temp ),
    byteval::GetConcreteByte
  );
  return temp;
}
const byteval::ByteVal &Seed::GetCurByteVal() const {
  return byte_vals[ cursor_pos ];
}
std::size_t Seed::GetCurLength() const {
  return byte_vals.size();
}
std::size_t Seed::GetUnfixedByteIndex() const {
  const std::size_t index = std::distance( byte_vals.begin(), std::find_if( byte_vals.begin(), byte_vals.end(), byteval::IsUnfixed ) );
  if( index == byte_vals.size() ) {
    throw exceptions::out_of_range( "index == byte_vals.size()", __FILE__, __LINE__ );
  }
  return index;
}
Direction Seed::GetByteCursorDir() const {
  return cursor_dir;
}
std::byte Seed::GetConcreteByteAt( std::size_t pos ) const {
  if( pos >= byte_vals.size() ) {
    throw exceptions::out_of_range( "pos >= byte_vals.size()", __FILE__, __LINE__ );
  }
  return byteval::GetConcreteByte( byte_vals[ pos ] );
}
std::byte Seed::GetConcreteByteAt() const {
  return GetConcreteByteAt( cursor_pos );
}
std::vector< std::byte > Seed::GetConcreteBytesFrom( std::size_t pos, std::size_t len ) const {
  if( pos + len >= byte_vals.size() ) {
    throw exceptions::out_of_range( "pos + len >= byte_vals.size()", __FILE__, __LINE__ );
  }
  std::vector< std::byte > temp;
  temp.reserve( len );
  const auto begin = std::next( byte_vals.begin(), pos );
  const auto end = std::next( begin, len );
  std::transform( begin, end, std::back_inserter( temp ), byteval::GetConcreteByte );
  return temp;
}
bool Seed::HasUnfixedByte() const {
  return std::find_if( byte_vals.begin(), byte_vals.end(), byteval::IsUnfixed ) != byte_vals.end();
}
bool Seed::IsUnfixedByteAt( std::size_t offset ) const {
  return byteval::IsUnfixed( byte_vals[ offset ] );
}
bool Seed::IsUnfixedByteAt() const {
  return IsUnfixedByteAt( cursor_pos );
}
std::size_t Seed::QueryLenToward( Direction direction_ ) const {
  if( direction_ == Direction::Stay ) {
    throw exceptions::invalid_argument( "queryLenToward() cannot be called with 'Stay'", __FILE__, __LINE__ );
  }
  else if( direction_ == Direction::Right ) {
    return byte_vals.size() - cursor_pos;
  }
  else if( direction_ == Direction::Left ) {
    return cursor_pos + 1;
  }
  else {
    throw exceptions::invalid_argument( "Unknown direction", __FILE__, __LINE__ );
  }
}
std::size_t Seed::QueryUpdateBoundLeft( const byteval::ByteVals &byte_vals_, std::size_t byte_cursor ) {
  constexpr auto len = MAX_CHUNK_LEN + 1u;
  const byteval::ByteVals::const_reverse_iterator begin = std::prev( byte_vals_.rend(), byte_cursor + 1u );
  const byteval::ByteVals::const_reverse_iterator end = ( byte_cursor > len ) ?
    std::prev( byte_vals_.rend(), byte_cursor - len ) :
    byte_vals_.rend();
  return std::min( int( std::distance( begin, std::find_if( begin, end, byteval::IsFixed ) ) ), MAX_CHUNK_LEN );
}
std::size_t Seed::QueryUpdateBoundRight( const byteval::ByteVals &byte_vals_, std::size_t byte_cursor ) {
  constexpr auto len = MAX_CHUNK_LEN + 1u;
  const byteval::ByteVals::const_iterator begin = std::next( byte_vals_.begin(), byte_cursor );
  const byteval::ByteVals::const_iterator end = ( byte_cursor + len < byte_vals_.size() ) ?
    std::next( byte_vals_.begin(), byte_cursor + len ) :
    byte_vals_.end();
  return std::min( int( std::distance( begin, std::find_if( begin, end, byteval::IsFixed ) ) ), MAX_CHUNK_LEN );
}
std::size_t Seed::QueryUpdateBound( Direction direction_ ) const {
  if( direction_ == Direction::Stay ) {
    throw exceptions::invalid_argument( "queryUpdateBound() cannot be called with 'Stay'", __FILE__, __LINE__ );
  }
  else if( direction_ == Direction::Left ) return QueryUpdateBoundLeft( byte_vals, cursor_pos );
  else if( direction_ == Direction::Right ) return QueryUpdateBoundRight( byte_vals, cursor_pos );
  else {
    throw exceptions::invalid_argument( "Unknown direction", __FILE__, __LINE__ );
  }
}
std::size_t Seed::QueryUpdateBound() const {
  return QueryUpdateBound( cursor_dir );
}
std::vector< std::byte > Seed::QueryNeighborBytes( Direction direction_ ) const {
  constexpr auto len = MAX_CHUNK_LEN + 1u;
  if( direction_ == Direction::Stay ) {
    throw exceptions::invalid_argument( "queryNeighborBytes() cannot be called with 'Stay'", __FILE__, __LINE__ );
  }
  else if( direction_ == Direction::Right ) {
    const auto upper_bound = std::min( byte_vals.size(), cursor_pos + len );
    std::vector< std::byte > temp;
    temp.reserve( len );
    if( cursor_pos < byte_vals.size() ) {
      std::transform(
        std::next( byte_vals.begin(), cursor_pos + 1u ),
        std::next( byte_vals.begin(), upper_bound ),
        std::back_inserter( temp ),
        byteval::GetConcreteByte
      );
    }
    return temp;
  }
  else if( direction_ == Direction::Left ) {
    const auto lower_bound = ( cursor_pos > len ) ? cursor_pos - len : size_t( 0 );
    std::vector< std::byte > temp;
    temp.reserve( len );
    if( cursor_pos > 0 ) {
      std::transform(
        std::next( byte_vals.begin(), lower_bound ),
        std::next( byte_vals.begin(), cursor_pos ),
        std::back_inserter( temp ),
        byteval::GetConcreteByte
      );
    }
    return temp;
  }
  else {
    throw exceptions::invalid_argument( "Unknown direction", __FILE__, __LINE__ );
  }
}
std::vector< std::byte > Seed::QueryNeighborBytes() const {
  return QueryNeighborBytes( cursor_dir );
}
Seed &Seed::ConstrainByteAtInplace( Direction direction_, std::size_t offset, std::byte low, std::byte upper ) {
  auto byte_cursor = cursor_pos;
  if( direction_ == Direction::Stay ) {
    throw exceptions::invalid_argument( "constrainByteAt() cannot be called with 'Stay'", __FILE__, __LINE__ );
  }
  else if( direction_ == Direction::Right ) byte_cursor += offset;
  else if( direction_ == Direction::Left ) byte_cursor -= offset;
  else {
    throw exceptions::invalid_argument( "Unknown direction", __FILE__, __LINE__ );
  }
  const auto new_byte_val = ( low != upper ) ? byteval::ByteVal( byteval::Interval{ low, upper } ) : byteval::ByteVal( byteval::Fixed{ low } );
  byte_vals[ byte_cursor ] = new_byte_val;
  return *this;
}
Seed Seed::ConstrainByteAt( Direction direction_, std::size_t offset, std::byte low, std::byte upper ) const {
  auto new_seed = *this;
  new_seed.ConstrainByteAtInplace( direction_, offset, low, upper );
  return new_seed;
}
Seed &Seed::ConstrainByteAtInplace( std::size_t offset, std::byte low, std::byte upper ) {
  return ConstrainByteAtInplace( cursor_dir, offset, low, upper );
}
Seed Seed::ConstrainByteAt( std::size_t offset, std::byte low, std::byte upper ) const {
  return ConstrainByteAt( cursor_dir, offset, low, upper );
}
Seed &Seed::FixCurBytesInplace( Direction direction_, const std::vector< std::byte > &bytes ) {
  const auto n_bytes = bytes.size();
  if( direction_ == Direction::Left && ( int( cursor_pos ) - int( n_bytes ) + 1 ) < 0 ) {
    throw exceptions::invalid_argument( "direction_ == Direction::Left && ( int( cursor_pos ) - int( n_bytes ) + 1 ) < 0", __FILE__, __LINE__ );
  }
  const auto start_pos = ( direction_ == Direction::Right ) ? int( cursor_pos ) : int( cursor_pos ) - int( n_bytes ) + 1;
  if( start_pos + n_bytes > byte_vals.size() ) {
    byte_vals.resize( start_pos + n_bytes, byteval::Undecided{ std::byte( 0u ) } );
  }
  std::transform( bytes.begin(), bytes.end(), std::next( byte_vals.begin(), start_pos ), []( auto v ) { return byteval::Fixed{ v }; } );
  return *this;
}
Seed Seed::FixCurBytes( Direction direction_, const std::vector< std::byte > &bytes ) const {
  auto new_seed = *this;
  new_seed.FixCurBytesInplace( direction_, bytes );
  return new_seed;
}
Seed &Seed::FixCurBytesInplace( const std::vector< std::byte > &bytes ) {
  return FixCurBytesInplace( cursor_dir, bytes );
}
Seed Seed::FixCurBytes( const std::vector< std::byte > &bytes ) const {
  return FixCurBytes( cursor_dir, bytes );
}
Seed &Seed::UpdateCurByteInplace( const byteval::ByteVal byte_val ) {
  byte_vals[ cursor_pos ] = byte_val;
  return *this;
}
Seed Seed::UpdateCurByte( const byteval::ByteVal byte_val ) const {
  auto new_seed = *this;
  new_seed.UpdateCurByteInplace( byte_val );
  return new_seed;
}
Seed &Seed::SetCursorPosInplace( std::size_t new_pos ) {
  cursor_pos = new_pos;
  return *this;
}
Seed Seed::SetCursorPos( std::size_t new_pos ) const {
  auto new_seed = *this;
  new_seed.SetCursorPosInplace( new_pos );
  return new_seed;
}
Seed &Seed::SetCursorDirInplace( Direction dir ) {
  cursor_dir = dir;
  return *this;
}
Seed Seed::SetCursorDir( Direction dir ) const {
  auto new_seed = *this;
  new_seed.SetCursorDirInplace( dir );
  return new_seed;
}
bool Seed::StepCursorInplace() {
  if( cursor_dir == Direction::Left && cursor_pos != 0 ) {
    SetCursorPosInplace( cursor_pos - 1u );
    return true;
  }
  else if( cursor_dir == Direction::Right && cursor_pos + 1u < byte_vals.size() ) {
    SetCursorPosInplace( cursor_pos + 1u );
    return true;
  }
  else {
    return false;
  }
}
std::optional< Seed > Seed::StepCursor() const {
  auto new_seed = *this;
  if( new_seed.StepCursorInplace() ) {
    return new_seed;
  }
  else {
    return std::nullopt;
  }
}
std::int64_t Seed::FindUnfixedByte( const byteval::ByteVals &bytes, std::size_t cur_index ) {
  const auto found = std::find_if( std::next( bytes.begin(), std::min( cur_index, bytes.size() ) ), bytes.end(), byteval::IsUnfixed );
  return ( found == bytes.end() ) ? -1 : std::distance( bytes.begin(), found );
}
std::int64_t Seed::FindUnfixedByteBackward( const byteval::ByteVals &bytes, std::size_t cur_index ) {
  const auto found = std::find_if( std::prev( bytes.rend(), cur_index + 1u ), bytes.rend(), byteval::IsUnfixed );
  return ( found == bytes.rend() ) ? -1 : std::distance( found, bytes.rend() ) - 1;
}
bool Seed::MoveToUnfixedByteInplace() {
  if( cursor_dir == Direction::Left ) {
    const auto offset = FindUnfixedByteBackward( byte_vals, cursor_pos );
    if( offset != -1 ) {
      SetCursorPosInplace( offset );
      return true;
    }
    else {
      return false;
    }
  }
  else if( cursor_dir == Direction::Right ) {
    const auto offset = FindUnfixedByte( byte_vals, cursor_pos );
    if( offset != -1 ) {
      SetCursorPosInplace( offset );
      return true;
    }
    else {
      return false;
    }
  }
  else return false;
}
std::optional< Seed > Seed::MoveToUnfixedByte() const {
  auto new_seed = *this;
  if( new_seed.MoveToUnfixedByteInplace() ) {
    return new_seed;
  }
  else {
    return std::nullopt;
  }
}
bool Seed::ProceedCursorInplace() {
  if( StepCursorInplace() ) {
    return MoveToUnfixedByteInplace();
  }
  else {
    return false;
  }
}
std::optional< Seed > Seed::ProceedCursor() const {
  auto new_seed = *this;
  if( new_seed.ProceedCursorInplace() ) {
    return new_seed;
  }
  else {
    return std::nullopt;
  }
}
Seed &Seed::SetByteCursorDirInplace( Direction dir ) {
  cursor_dir = dir;
  return *this;
}
Seed Seed::SetByteCursorDir( Direction dir ) const {
  auto new_seed = *this;
  new_seed.SetByteCursorDirInplace( dir );
  return new_seed;
}
/*
  let relocateCursor seed =
    let curByteVal = getCurByteVal seed
    let leftwardSeed = setByteCursorDir seed Left
    let leftwardSeeds = // Avoid sampling at the same offset.
      if ByteVal.isSampledByte curByteVal then
        match stepCursor leftwardSeed with
        | None -> [] | Some s -> [ s ]
      else [ leftwardSeed ]
    let rightwardSeed = setByteCursorDir seed Right
    let rightwardSeeds =
      match stepCursor rightwardSeed with
      | None -> [] | Some s -> [ s ]
    List.choose moveToUnfixedByte (leftwardSeeds @ rightwardSeeds)
*/
std::vector< Seed > Seed::RelocateCursor() const {
  const auto cur_byte_val = GetCurByteVal();
  const auto leftward_seed = SetByteCursorDir( Direction::Left );
  auto leftward_seeds = std::optional< Seed >();
  if( byteval::IsSampledByte( cur_byte_val ) ) {
    auto stepped = leftward_seed.StepCursor();
    if( stepped ) {
      leftward_seeds = stepped;
    }
  }
  else {
    leftward_seeds = leftward_seed;
  }
  const auto rightward_seed = SetByteCursorDir( Direction::Right );
  auto rightward_seeds = std::optional< Seed >();
  auto stepped = rightward_seed.StepCursor();
  if( stepped ) {
    rightward_seeds = stepped;
  }
  std::vector< Seed > results;
  if( leftward_seeds ) {
    auto unfixed = leftward_seeds->MoveToUnfixedByteInplace();
    if( unfixed ) results.push_back( *leftward_seeds );
  }
  if( rightward_seeds ) {
    auto unfixed = rightward_seeds->MoveToUnfixedByteInplace();
    if( unfixed ) results.push_back( *rightward_seeds );
  }
  return results;
}

namespace {
  // Auxiliary function for byteValsToStr() that handles 'Untouched' ByteVals.
std::string UntouchedToStr(
  const byteval::ByteVals::const_iterator &untouched_list_begin,
  const byteval::ByteVals::const_iterator &untouched_list_end
) {
  if( untouched_list_begin == untouched_list_end ) return "";
  else if( std::distance( untouched_list_begin, untouched_list_end ) < 4u ) {
    std::string temp = " ";
    bool init = true;
    for( const auto &v: boost::make_iterator_range( untouched_list_begin, untouched_list_end ) ) {
      if( init ) init = false;
      else temp += " ";
      temp += ToString( v );
    }
    return temp;
  }
  else {
    std::string temp = " ...";
    temp += std::to_string( std::distance( untouched_list_begin, untouched_list_end ) );
    temp += "bytes...";
    return temp;
  }
}

std::string &ByteValsToStr(
  byteval::ByteVals &accum_untouched,
  std::string &accum_strs,
  byteval::ByteVals::const_iterator byte_vals_begin,
  const byteval::ByteVals::const_iterator &byte_vals_end
) {
  while( true )  {
    if( byte_vals_begin == byte_vals_end ) {
      accum_strs += UntouchedToStr( accum_untouched.begin(), accum_untouched.end() );
      return accum_strs;
    }
    else {
      std::visit(
        [&]( const auto &v ) {
          if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, byteval::Untouched > ) {
            accum_untouched.push_back( v );
          }
          else {
            accum_strs += UntouchedToStr( accum_untouched.begin(), accum_untouched.end() );
            accum_untouched.clear();
            accum_strs += " ";
            accum_strs += ToString( v );
          }
        },
        *byte_vals_begin
      );
      byte_vals_begin = std::next( byte_vals_begin );
    }
  }
}

}

std::string Seed::ToString() const {
  byteval::ByteVals accum_untouched;
  std::string accum_strs;
  auto byte_str = ByteValsToStr( accum_untouched, accum_strs, byte_vals.begin(), byte_vals.end() );
  byte_str += " (";
  byte_str += std::to_string( cursor_pos );
  byte_str += ") (";
  byte_str += eclipser::ToString( cursor_dir );
  byte_str += ")";
  return byte_str;
}

void to_json( nlohmann::json &dest, const Seed &src ) {
  dest = nlohmann::json::object();
  dest[ "byte_vals" ] = nlohmann::json::array();
  for( const auto &v: src.byte_vals ) {
    dest[ "byte_vals" ].push_back( v );
  }
  dest[ "cursor_pos" ] = src.cursor_pos;
  dest[ "cursor_dir" ] = src.cursor_dir;
  dest[ "source" ] = src.source;
}

void from_json( const nlohmann::json &src, Seed &dest ) {
  dest = Seed();
  if( src.is_object() ) {
    if( src.find( "byte_vals" ) != src.end() ) {
      /*std::transform(
        src[ "byte_vals" ].begin(), src[ "byte_vals" ].end(),        
	std::back_inserter( dest.byte_vals ),
	[]( auto v ) { return std::byte( v ); }
      );*/
      if( src.find( "cursor_pos" ) != src.end() ) {
        dest.cursor_pos = src[ "current_pos" ];
      }
    }
    if( src.find( "cursor_dir" ) != src.end() ) {
      dest.cursor_pos = src[ "cursor_dir" ];
    }
    if( src.find( "source" ) != src.end() ) {
      dest.source = src[ "source" ].get< InputSource >();
    }
  }
}

}


