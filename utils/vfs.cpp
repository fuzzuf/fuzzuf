#include <algorithm>
#include <fuzzuf/utils/filesystem.hpp>
#include <fuzzuf/utils/vfs.hpp>
#include <fuzzuf/exceptions.hpp>

namespace fuzzuf::utils::vfs {

VFS::VFS(
  std::vector< fs::path > &&allowed_path_
) {
  if( allowed_path_.empty() )
    throw exceptions::invalid_argument( "No any paths are allowed", __FILE__, __LINE__ );
  std::vector< fs::path > duplicated_allowed_path;
  duplicated_allowed_path.reserve( allowed_path_.size() );
  if( !allowed_path_[ 0 ].has_root_directory() )
    throw exceptions::invalid_argument( "First allowed path must contain root directory", __FILE__, __LINE__ );
  {
    auto can = allowed_path_[ 0 ].lexically_normal();
    current_workdir = can;
  } 
  std::transform(
    allowed_path_.begin(),
    allowed_path_.end(),
    std::back_inserter( duplicated_allowed_path ),
    [this]( const auto &v ) {
      auto abs = Absolute( v );
      auto can = abs.lexically_normal();
      return can;
    }
  );
  std::sort(
    duplicated_allowed_path.begin(),
    duplicated_allowed_path.end()
  );
  allowed_path->push_back( std::move( duplicated_allowed_path[ 0 ] ) );
  current_workdir = (*allowed_path)[ 0 ];
  fs::path prev = duplicated_allowed_path[ 0 ];
  auto prev_len = std::distance( prev.begin(), prev.end() );
  allowed_path.reset( new std::vector< fs::path >{} );
  for(
    auto cur = std::next( duplicated_allowed_path.begin() );
    cur != duplicated_allowed_path.end();
    ++cur
  ) {
    auto cur_len = std::distance( cur->begin(), cur->end() );
    if( prev_len > cur_len ) {
      prev = *cur;
      allowed_path->push_back( std::move( *cur ) );
      prev_len = std::distance( prev.begin(), prev.end() );
    }
    else if( !std::equal(
      prev.begin(), prev.end(),
      cur->begin(), std::next( cur->begin(), prev_len )
    ) ) {
      prev = *cur;
      allowed_path->push_back( std::move( *cur ) );
      prev_len = std::distance( prev.begin(), prev.end() );
    }
  }
  if( std::find_if(
    allowed_path->begin(),
    allowed_path->end(),
    [rn=(*allowed_path)[ 0 ].root_name()]( const auto &p ) {
      return p.root_name() != rn;
    }
  ) != allowed_path->end() )
    throw exceptions::invalid_argument( "Inconsistent root name", __FILE__, __LINE__ );
}

LocalFilesystem::LocalFilesystem(
  std::vector< fs::path > &&allowed_path_
) : VFS( std::move( allowed_path_ ) ) {
  if( std::find_if(
    allowed_path->begin(),
    allowed_path->end(),
    []( const auto &p ) {
      return !fs::exists( p );
    }
  ) != allowed_path->end() )
    throw exceptions::invalid_argument( "The path doesn't exist", __FILE__, __LINE__ );
}

std::optional< fs::path > VFS::IsAllowedPath( const fs::path &p ) const {
  auto abs = Absolute( p );
  auto requested = abs.lexically_normal();
  auto closest = std::lower_bound(
    allowed_path->begin(),
    allowed_path->end(),
    requested
  );
  if( closest == allowed_path->end() ) return std::nullopt;
  const auto closest_len = std::distance( closest->begin(), closest->end() );
  const auto requested_len = std::distance( requested.begin(), requested.end() );
  if( closest_len > requested_len ) return std::nullopt;
  if( !std::equal(
    closest->begin(), closest->end(),
    requested.begin(), std::next( requested.begin(), closest_len )
  ) ) return std::nullopt;
  return requested;
}
fs::path VFS::SanitizePath( const fs::path &p ) const {
  auto sanitized = IsAllowedPath( p );
  if( !sanitized ) throw exceptions::invalid_file( "Access to the path is not allowed.", __FILE__, __LINE__ );
  return *sanitized;
}

fs::path VFS::CurrentPath() const {
  return current_workdir;
}
void VFS::CurrentPath( const fs::path &p ) {
  current_workdir = SanitizePath( p );
}
fs::path VFS::Absolute( const fs::path &p ) const {
  if( p.has_root_directory() ) return p;
  return current_workdir / p;
}
fs::path VFS::Relative( const fs::path &p ) const {
  if( p.is_relative() ) return p;
  return p.lexically_relative( current_workdir );
}
fs::path LocalFilesystem::ReadSymlink( const fs::path &p ) const {
  return fs::read_symlink( p );
}
void LocalFilesystem::Copy(const fs::path& from, const fs::path& to) {
  fs::copy( SanitizePath( from ), SanitizePath( to ) );
}
void LocalFilesystem::Copy(const fs::path& from, const fs::path& to, fs::copy_options options) {
  fs::copy( SanitizePath( from ), SanitizePath( to ), options );
}
bool LocalFilesystem::CopyFile(const fs::path& from, const fs::path& to) {
  return fs::copy_file( SanitizePath( from ), SanitizePath( to ) );
}
bool LocalFilesystem::CopyFile(const fs::path& from, const fs::path& to, fs::copy_options options) {
  return fs::copy_file( SanitizePath( from ), SanitizePath( to ), options );
}
void LocalFilesystem::CopySymlink(const fs::path& existing_symlink, const fs::path& new_symlink) {
  fs::copy_symlink( SanitizePath( existing_symlink ), SanitizePath( new_symlink ) );
}
void LocalFilesystem::CreateDirectory(const fs::path& p) {
  fs::create_directory( SanitizePath( p ) );
}
bool LocalFilesystem::CreateDirectory(const fs::path& p, const fs::path& existing_p) {
  return fs::create_directory( SanitizePath( p ), SanitizePath( existing_p ) );
}
bool LocalFilesystem::CreateDirectories(const fs::path& p) {
  return fs::create_directories( SanitizePath( p ) );
}
void LocalFilesystem::CreateDirectorySymlink(const fs::path& to, const fs::path& new_symlink) {
  fs::create_directory_symlink( SanitizePath( to ), SanitizePath( new_symlink ) );
}
void LocalFilesystem::CreateHardLink(const fs::path& to, const fs::path& new_hard_link) {
  fs::create_hard_link( SanitizePath( to ), SanitizePath( new_hard_link ) );
}
void LocalFilesystem::CreateSymlink(const fs::path& to, const fs::path& new_symlink) {
  fs::create_symlink( SanitizePath( to ), SanitizePath( new_symlink ) );
}
void LocalFilesystem::Permissions(const fs::path& p, fs::perms prms, fs::perm_options opts ) {
  fs::permissions( SanitizePath( p ), prms, opts );
}
bool LocalFilesystem::Remove(const fs::path& p) {
  return fs::remove( SanitizePath( p ) );
}
std::uintmax_t LocalFilesystem::RemoveAll(const fs::path& p) {
  return fs::remove_all( SanitizePath( p ) );
}
void LocalFilesystem::Rename(const fs::path& old_p, const fs::path& new_p) {
  fs::rename( SanitizePath( old_p ), SanitizePath( new_p ) );
}
void LocalFilesystem::ResizeFile(const fs::path& p, std::uintmax_t new_size) {
  fs::resize_file( SanitizePath( p ), new_size );
}
bool LocalFilesystem::Exists(const fs::path& p) {
  return fs::exists( SanitizePath( p ) );
}
bool LocalFilesystem::Equivalent(const fs::path& p1, const fs::path& p2) {
  return fs::equivalent( SanitizePath( p1 ), SanitizePath( p2 ) );
}
std::uintmax_t LocalFilesystem::FileSize(const fs::path& p) {
  return fs::file_size( SanitizePath( p ) );
}
std::uintmax_t LocalFilesystem::HardLinkCount(const fs::path& p) {
  return fs::hard_link_count( SanitizePath( p ) );
}
bool LocalFilesystem::IsRegularFile(const fs::path& p) {
  return fs::is_regular_file( SanitizePath( p ) );
}
bool LocalFilesystem::IsDirectory(const fs::path& p) {
  return fs::is_directory( SanitizePath( p ) );
}
bool LocalFilesystem::IsSymlink(const fs::path& p) {
  return fs::is_symlink( SanitizePath( p ) );
}
bool LocalFilesystem::IsBlockFile(const fs::path& p) {
  return fs::is_block_file( SanitizePath( p ) );
}
bool LocalFilesystem::IsCharacterFile(const fs::path& p) {
  return fs::is_character_file( SanitizePath( p ) );
}
bool LocalFilesystem::IsFifo(const fs::path& p) {
  return fs::is_fifo( SanitizePath( p ) );
}
bool LocalFilesystem::IsSocket(const fs::path& p) {
  return fs::is_socket( SanitizePath( p ) );
}
bool LocalFilesystem::IsOther(const fs::path& p) {
  return fs::is_other( SanitizePath( p ) );
}
bool LocalFilesystem::IsEmpty(const fs::path& p) {
  return fs::is_empty( SanitizePath( p ) );
}
fs::file_time_type LocalFilesystem::LastWriteTime(const fs::path& p) {
  return fs::last_write_time( SanitizePath( p ) );
}
fs::space_info LocalFilesystem::Space(const fs::path& p) {
  return fs::space( SanitizePath( p ) );
}
fs::directory_iterator LocalFilesystem::OpenDirectory( const fs::path &p ) {
  return fs::directory_iterator( SanitizePath( p ), fs::directory_options::skip_permission_denied );
}
fs::recursive_directory_iterator LocalFilesystem::OpenDirectoryRecursive( const fs::path &p ) {
  return fs::recursive_directory_iterator( SanitizePath( p ), fs::directory_options::skip_permission_denied );
}
mapped_file_t LocalFilesystem::Mmap( const fs::path &p, unsigned int flags, bool populate ) {
  return map_file( SanitizePath( p ).string(), flags, populate );
}
std::fstream LocalFilesystem::Open( const fs::path &p, std::ios_base::openmode mode ) {
  return std::fstream( SanitizePath( p ).string(), mode );
}

}

