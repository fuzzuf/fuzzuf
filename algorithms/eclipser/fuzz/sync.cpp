#if __GNUC__ >= 8
#include <charconv>
#endif
#include <fcntl.h>
#include <fuzzuf/utils/map_file.hpp>
#include <fuzzuf/algorithms/eclipser/core/executor.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/seed_queue.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/test_case.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/sync.hpp>

namespace fuzzuf::algorithm::eclipser::sync {

namespace {
std::unordered_map< std::string, int > map_imports;

std::optional< int >
TryParseTCNum(
  const fs::path &tc_path
) {
  const auto tc_name = tc_path.filename().string();
  if( tc_name.find( "id:" ) != 0u ) {
    return std::nullopt;
  }
  else if( tc_name.size() < 9u ) {
    return std::nullopt;
  }
  else {
    int value = 0;
#if __GNUC__ >= 8
    const auto result = std::from_chars(
      std::next( tc_name.data(), 3 ),
      std::next( tc_name.data(), 9 ),
      value
    );
    if( result.ec != std::errc{} ) {
      return std::nullopt;
    }
#else
    bool is_number = true;
    for( unsigned int i = 3u; i != 9u; ++i ) {
      value *= 10;
      if( tc_name[ i ] >= '0' && tc_name[ i ] <= '9' ) {
        value |= tc_name[ i ] - '0';
      }
      else {
        is_number = false;
	break;
      }
    }
    if( !is_number ) {
      return std::nullopt;
    }
#endif
    return value;
  }
}

seed_queue::SeedQueue &ImportSeed(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const std::string tc_path,
  seed_queue::SeedQueue &seed_queue
) {
  const auto mapped = utils::map_file(tc_path, O_RDONLY, true);
  std::vector< std::byte > tc_bytes;
  std::transform(
    mapped.begin(),
    mapped.end(),
    std::back_inserter( tc_bytes ),
    []( const auto &v ) { return std::byte( v ); }
  );
  auto seed = seed::Seed( opt.fuzz_source, tc_bytes );
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
  const auto [signal,cov_gain] = executor::GetCoverage( sink, opt, seed );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
  const auto priority_maybe = priority::OfCoverageGain( cov_gain );
  if( priority_maybe ) {
    seed_queue.EnqueueInplace( *priority_maybe, seed );
  }
  return seed_queue;
}

void SyncTestCase(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  int max_import,
  seed_queue::SeedQueue &acc_seed_queue,
  int &acc_max_import,
  const fs::path &tc_path
) {
  const auto num_maybe = TryParseTCNum( tc_path );
  if( num_maybe ) {
    if( *num_maybe > max_import ) { // Unhandled test case ID.
      if( opt.verbosity >= 2 ) {
        std::string message = "Synchronizing seed queue with ";
        message += tc_path.string();
        message += "\n";
        sink( std::move( message ) );
      }
      acc_max_import = ( *num_maybe > acc_max_import ) ? *num_maybe : acc_max_import;
      ImportSeed( sink, opt, tc_path.string(), acc_seed_queue );
    }
  }
}

seed_queue::SeedQueue &SyncFromDir(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  seed_queue::SeedQueue &seed_queue,
  const std::string &dir
) {
  const auto existing = map_imports.find( dir );
  auto max_import = ( existing != map_imports.end() ) ? existing->second : 0;
  const auto tc_dir = fs::path( dir ) / "queue";
  int acc_max_import = max_import;
  for( const auto &d: fs::directory_iterator( tc_dir ) ) {
    SyncTestCase( sink, opt, max_import, seed_queue, acc_max_import, d.path() );
  }
  if( acc_max_import > max_import ) map_imports[ dir ] = acc_max_import;
  return seed_queue;
}

}

seed_queue::SeedQueue &Run(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  seed_queue::SeedQueue &seed_queue
) {
  const auto out_dir = fs::absolute( fs::path( opt.out_dir ) );
  const auto sync_dir = fs::absolute( fs::path( opt.sync_dir ) );
  std::vector< fs::path > sub_dirs;
  for( const auto &d: fs::directory_iterator( sync_dir ) ) {
    if( d.path() != out_dir ) { // Exclude our own output.
      if( fs::is_directory( d.path() ) ) {
        sub_dirs.push_back( d.path() );
      }
    }
  }
  executor::DisableRoundStatistics();
  test_case::DisableRoundStatistics();
  for( const auto &d: sub_dirs ) {
    SyncFromDir( sink, opt, seed_queue, d.string() );
  }
  executor::EnableRoundStatistics();
  test_case::EnableRoundStatistics();
  return seed_queue;
}

}

