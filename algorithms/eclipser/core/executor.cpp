#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/karma.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/algorithms/eclipser/core/executor.hpp>
#include <fuzzuf/algorithms/eclipser/core/seed.hpp>
#include <fuzzuf/algorithms/eclipser/core/utils.hpp>
#include <fuzzuf/algorithms/eclipser/core/options.hpp>
#include <fuzzuf/algorithms/eclipser/core/branch_info.hpp>
#include <fuzzuf/algorithms/eclipser/core/failwith.hpp>
#include <fuzzuf/algorithms/eclipser/core/config.hpp>
#include <fuzzuf/utils/map_file.hpp>

extern "C" {
int exec(
  int /*argc*/,
  char ** /*args*/,
  int /*stdin_size*/,
  char * /*stdin_data*/,
  std::uint64_t /*timeout*/
);

int exec_fork_coverage(
  std::uint64_t /*timeout*/,
  int /*stdin_size*/,
  char * /*stdin_data*/
);

int exec_fork_branch( 
  std::uint64_t /*timeout*/,
  int /*stdin_size*/,
  char * /*stdin_data*/,
  std::uint64_t /*targ_addr*/,
  std::uint32_t /*targ_index*/,
  int /*measure_cov*/
);

void kill_forkserver();
pid_t init_forkserver_coverage(int argc, char** args, uint64_t timeout);
pid_t init_forkserver_branch(int argc, char** args, uint64_t timeout);
void initialize_exec(void);
}

namespace fuzzuf::algorithm::eclipser::executor {

namespace {
  std::string branch_log = "";
  std::string coverage_log = "";
  std::string bitmap_log = "";
  std::string dbg_log = "";
  bool fork_server_on = false;
  bool round_statistics_on = false;
  int round_execs = 0;
}

void EnableRoundStatistics() {
  round_statistics_on = true;
}

void DisableRoundStatistics() {
  round_statistics_on = false;
}

int GetRoundExecs() {
  return round_execs;
}

// Increment only if roundStatisticsOn flag is set. We don't want the executions
// for the synchronization with AFL to affect the efficiency calculation.
void IncrRoundExecs() {
  if( round_statistics_on ) {
    round_execs += 1;
  }
}

void ResetRoundExecs() {
  round_execs = 0;
}

namespace {

void SetEnvForBranch(
  std::uint64_t addr,
  std::uint32_t idx,
  CoverageMeasure cov_measure
) {
  namespace karma = boost::spirit::karma;
  karma::uint_generator< std::uint64_t, 16 > hex64;
  std::array< char, 17u > addr_str;
  addr_str[ 16 ] = 0;
  karma::generate(
    addr_str.data(),
    karma::right_align( 16, '0' )[ hex64 ],
    addr
  );
  std::array< char, 17u > idx_str;
  idx_str[ 16 ] = 0;
  karma::generate(
    idx_str.data(),
    karma::right_align( 16, '0' )[ hex64 ],
    idx
  );
  std::array< char, 11u > measure_str{ 0 };
  karma::generate(
    measure_str.data(),
    karma::int_,
    int( cov_measure )
  );
  setenv("ECL_BRANCH_ADDR", addr_str.data(), 1 );
  setenv("ECL_BRANCH_IDX", idx_str.data(), 1 );
  setenv("ECL_MEASURE_COV", measure_str.data(), 1 );
}

void SetupFile( const std::function<void(std::string &&)> &sink, const seed::Seed &seed ) {
  std::visit(
    [&]( const auto &v ) {
      if constexpr ( std::is_same_v< fuzzuf::utils::type_traits::RemoveCvrT< decltype( v ) >, FileInput > ) {
        WriteFile( sink, v.filepath, seed.Concretize() );
      }
    },
    seed.source
  );
}

std::vector< std::byte > PrepareStdIn( const seed::Seed &seed ) {
  return std::visit(
    [&]( const auto &v ) {
      if constexpr ( std::is_same_v< fuzzuf::utils::type_traits::RemoveCvrT< decltype( v ) >, StdInput > ) {
        return seed.Concretize();
      }
      else {
        return std::vector< std::byte >();
      }
    },
    seed.source
  );
}

CoverageGain ParseCoverage( const std::string &p ) {
  auto range = fuzzuf::utils::map_file( p, O_RDONLY, false );
  BranchTrace branch_trace;
  auto iter = range.begin().get();
  const auto end = range.end().get();
  namespace qi = boost::spirit::qi;
  std::uint64_t head = 0u;
  if( !( qi::parse( iter, end, qi::ulong_long, head ) ) )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    throw exceptions::invalid_file( "Unable to parse coverage", __FILE__, __LINE__ );
  }
  return ( head == 1ull ) ? CoverageGain::NewEdge : CoverageGain::NoGain;
}

}

bool Is64Bit( Arch arch ) {
  return arch == Arch::X64;
}

void IncrRoundExec() {
  if( round_statistics_on ) {
    ++round_execs;
  }
}

fs::path BuildDir() {
  return fs::canonical( "/proc/self/exe" ).parent_path();
}

fs::path SelectTracer( Tracer tracer, Arch arch ) {
  if( tracer == Tracer::Coverage && arch == Arch::X86 ) return BuildDir() / "qemu-trace-coverage-x86";
  else if( tracer == Tracer::Coverage && arch == Arch::X64 ) return BuildDir() / "qemu-trace-coverage-x64";
  else if( tracer == Tracer::Branch && arch == Arch::X86 ) return BuildDir() / "qemu-trace-branch-x86";
  else if( tracer == Tracer::Branch && arch == Arch::X64 ) return BuildDir() / "qemu-trace-branch-x64";
  else if( tracer == Tracer::BBCount && arch == Arch::X86 ) return BuildDir() / "qemu-trace-bbcount-x86";
  else if( tracer == Tracer::BBCount && arch == Arch::X64 ) return BuildDir() / "qemu-trace-bbcount-x64";
  else {
    throw exceptions::invalid_argument( "The tracer and architecture combination is not supported", __FILE__, __LINE__ );
  }
}

std::vector< std::string > SplitCmdLineArg(
  const std::string &arg_str
) {
  if( arg_str.empty() ) {
    return std::vector< std::string >();
  }
  auto iter = arg_str.begin();
  const auto end = arg_str.end();
  namespace qi = boost::spirit::qi;
  std::vector< std::string > dest;
  const bool result = qi::parse(
    iter,
    end,
    qi::as_string[ 
      *( qi::standard::char_ - qi::standard::space )
    ] % qi::standard::space,
    dest
  ) && iter == end;
  assert( result );
  dest.erase(
    std::remove(
      dest.begin(),
      dest.end(),
      std::string()
    ),
    dest.end()
  );
  return dest;
}

Signal RunTracer(
  Tracer tracerType,
  const options::FuzzOption &opt,
  const std::vector< std::byte > &stdin
) {
  IncrRoundExec();
  const auto timeout = opt.exec_timeout;
  auto raw_args = opt.raw_args.find( tracerType );
  assert( raw_args != opt.raw_args.end() );
  const int argc = raw_args->second.size();
  auto r = Signal( exec( argc, const_cast< char** >( raw_args->second.data() ), stdin.size(), reinterpret_cast< char* >( const_cast< std::byte* >( stdin.data() ) ), timeout ) );
  return r;
}

namespace {

void InitializeForkServer(
  const options::FuzzOption &opt
) {
  fork_server_on = true;
  {
    auto raw_args = opt.raw_args.find( Tracer::Coverage );
    assert( raw_args != opt.raw_args.end() );
    const auto pid_coverage = init_forkserver_coverage( raw_args->second.size(), const_cast< char** >( raw_args->second.data() ), opt.exec_timeout );
    if( pid_coverage == -1 )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
    {
      failwith( "Failed to initialize fork server for coverage tracer" );
      return; // unreachable
    }
  }
  {
    auto raw_args = opt.raw_args.find( Tracer::Branch );
    assert( raw_args != opt.raw_args.end() );
    const auto pid_coverage = init_forkserver_branch( raw_args->second.size(), const_cast< char** >( raw_args->second.data() ), opt.exec_timeout );
    if( pid_coverage == -1 ) {
      failwith( "Failed to initialize fork server for branch tracer" );
      return; // unreachable
    }
  }
}

}

void Initialize(
  const options::FuzzOption &opt
) {
  const fs::path out_dir = opt.out_dir;
  branch_log = ( out_dir / ".branch" ).string();
  coverage_log = ( out_dir / ".coverage" ).string();
  bitmap_log = ( out_dir / ".bitmap" ).string();
  dbg_log = ( out_dir / ".debug" ).string();
  const auto branch_log_full = fs::absolute( out_dir / ".branch" );
  setenv( "ECL_BRANCH_LOG", fs::absolute( out_dir / ".branch" ).c_str(), 1 );
  setenv( "ECL_COVERAGE_LOG", fs::absolute( out_dir / ".coverage" ).c_str(), 1 );
  fs::create_directories( out_dir );
  if( fs::exists( out_dir / ".bitmap" ) ) {
    fs::remove( out_dir / ".bitmap" );
  }
  std::ofstream{ bitmap_log };
  fs::resize_file( out_dir / ".bitmap", BITMAP_SIZE );
  setenv( "ECL_BITMAP_LOG", fs::absolute( out_dir / ".bitmap" ).c_str(), 1 );
  initialize_exec();
  if( opt.fork_server ) {
    setenv( "ECL_FORK_SERVER", "1", 1 );
    InitializeForkServer( opt );
  }
  else {
    setenv( "ECL_FORK_SERVER", "0", 1 );
  }
}

void AbandonForkServer( const std::function<void(std::string &&)> &sink ) {
  Log( sink, "Abandon fork server" );
  fork_server_on = false;
  setenv("ECL_FORK_SERVER", "0", 1 );
  kill_forkserver();
}


Signal RunCoverageTracerForked(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const std::vector< std::byte > &stdin
) {
  IncrRoundExec();
  const auto timeout = opt.exec_timeout;
  const auto std_len = stdin.size();
  const auto signal = Signal( exec_fork_coverage( timeout, std_len, reinterpret_cast< char* >( const_cast< std::byte* >( stdin.data() ) ) ) );
  if( signal == Signal::ERROR ) AbandonForkServer( sink );
  return signal;
}

Signal RunBranchTracerForked(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const std::vector< std::byte > &stdin,
  std::uint64_t addr,
  std::uint32_t idx,
  CoverageMeasure cov_measure
) {
  IncrRoundExec();
  const auto timeout = opt.exec_timeout;
  const auto std_len = stdin.size();
  const auto cov_enum = int( cov_measure );
  const auto signal = Signal( exec_fork_branch( timeout, std_len, reinterpret_cast< char* >( const_cast< std::byte* >( stdin.data() ) ), addr, idx, cov_enum ) );
  if( signal == Signal::ERROR ) AbandonForkServer( sink );
  return signal;
}

std::pair< Signal, CoverageGain > GetCoverage(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed
) {
  SetupFile( sink, seed );
  const auto stdin = PrepareStdIn( seed );
  const auto exit_sig = fork_server_on ?
    RunCoverageTracerForked( sink, opt, stdin ):
    RunTracer( Tracer::Coverage, opt, stdin );
  const auto coverage_gain = ParseCoverage( coverage_log );
  return std::make_pair( exit_sig, coverage_gain );
}

namespace {

template< typename T >
std::optional< std::pair< T, T > > ReadPair( std::fstream &f ) {
  T oprnd1;
  f.read( reinterpret_cast< char* >( &oprnd1 ), sizeof( oprnd1 ) );
  if( f.fail() )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    return std::nullopt;
  }
  T oprnd2;
  f.read( reinterpret_cast< char* >( &oprnd2 ), sizeof( oprnd2 ) );
  if( f.fail() )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    return std::nullopt;
  }
  return std::make_pair( oprnd1, oprnd2 );
}

std::optional< BranchInfo > ParseBranchTraceLog(
  const std::function<void(std::string &&)> &sink, 
  const options::FuzzOption &opt,
  std::fstream &f,
  const BigInt &try_val
) {
  const auto arch = opt.architecture;
  std::uint64_t addr = 0ul;
  if( Is64Bit( arch ) ) {
    std::uint64_t temp;
    f.read( reinterpret_cast< char* >( &temp ), sizeof( std::uint64_t ) );
#ifdef __BIG_ENDIAN__
    temp = le64toh( temp );    
#endif
    addr = f.fail() ? 0ul : temp;
  }
  else {
    std::uint32_t temp;
    f.read( reinterpret_cast< char* >( &temp ), sizeof( std::uint32_t ) );
#ifdef __BIG_ENDIAN__
    temp = le64toh( temp );    
#endif
    addr = f.fail() ? 0ul : temp;
  }
  if( addr == 0ul )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    return std::nullopt;
  }
  std::uint8_t type_info;
  f.read( reinterpret_cast< char* >( &type_info ), sizeof( type_info ) );
  if( f.fail() )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    return std::nullopt;
  }
  const auto op_size = type_info & 0x3Fu;
  const auto raw_br_type = type_info >> 6;
  auto br_type = CompareType::Equality;
  if( raw_br_type == 0u ) {
    br_type = CompareType::Equality;
  }
  else if( raw_br_type == 1u ) {
    br_type = CompareType::SignedSize;
  }
  else if( raw_br_type == 2u ) {
    br_type = CompareType::UnsignedSize;
  }
  else
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    Log( sink, "[Warning] Unexpected branch type" );
    failwith( "Unmatched" );
    return std::nullopt; // unreachable
  }
  std::uint64_t oprnd1;
  std::uint64_t oprnd2;
  if( op_size == 1u ) {
    const auto oprnd_maybe = ReadPair< std::uint8_t >( f );
    if( !oprnd_maybe ) {
      return std::nullopt;
    }
    oprnd1 = oprnd_maybe->first;
    oprnd2 = oprnd_maybe->second;
  }
  else if( op_size == 2u ) {
    const auto oprnd_maybe = ReadPair< std::uint16_t >( f );
    if( !oprnd_maybe ) {
      return std::nullopt;
    }
#ifdef __BIG_ENDIAN__
    oprnd1 = le16toh( oprnd_maybe->first );
    oprnd2 = le16toh( oprnd_maybe->second );
#else
    oprnd1 = oprnd_maybe->first;
    oprnd2 = oprnd_maybe->second;
#endif
  }
  else if( op_size == 4u ) {
    const auto oprnd_maybe = ReadPair< std::uint32_t >( f );
    if( !oprnd_maybe ) {
      return std::nullopt;
    }
#ifdef __BIG_ENDIAN__
    oprnd1 = le32toh( oprnd_maybe->first );
    oprnd2 = le32toh( oprnd_maybe->second );
#else
    oprnd1 = oprnd_maybe->first;
    oprnd2 = oprnd_maybe->second;
#endif
  }
  else if( op_size == 8u ) {
    const auto oprnd_maybe = ReadPair< std::uint64_t >( f );
    if( !oprnd_maybe ) {
      return std::nullopt;
    }
#ifdef __BIG_ENDIAN__
    oprnd1 = le64toh( oprnd_maybe->first );
    oprnd2 = le64toh( oprnd_maybe->second );
#else
    oprnd1 = oprnd_maybe->first;
    oprnd2 = oprnd_maybe->second;
#endif
  }
  else
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    Log( sink, "[Warning] Unexpected operand size" );
    failwith( "Unmatched" );
    return BranchInfo{}; // unreachable
  }
  const BigInt dist = BigInt( oprnd1 ) - BigInt( oprnd2 );
  return BranchInfo{
    addr,
    br_type,
    try_val,
    op_size,
    oprnd1,
    oprnd2,
    dist
  };
}

std::vector< BranchInfo > ReadBranchTrace(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const std::string &filename,
  const BigInt &try_val
) {
  if( !fs::exists( filename ) ) {
    return std::vector< BranchInfo >{};
  }
  std::fstream f( filename, std::ios::in|std::ios::binary );
  std::vector< BranchInfo > temp;
  while( true ) {
    const auto branch_info = ParseBranchTraceLog( sink, opt, f, try_val );
    if( branch_info ) {
      temp.push_back( *branch_info );
    }
    else {
      break;
    }
  }
  return temp;
}

std::optional< BranchInfo > TryReadBranchInfo(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const std::string &filename,
  const BigInt &try_val
) {
  auto temp = ReadBranchTrace( sink, opt, filename, try_val );
  if( temp.size() == 1u )
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[likely]]
#endif  
  {
    return std::move( temp[ 0 ] );
  }
  else {
    return std::nullopt;
  }
}

}

std::tuple< Signal, CoverageGain, std::vector< BranchInfo > >
GetBranchTrace(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  const BigInt &try_val
) {
  SetupFile( sink, seed );
  const auto stdin = PrepareStdIn( seed );
  Signal exit_sig;
  if( fork_server_on ) {
    exit_sig = RunBranchTracerForked( sink, opt, stdin, 0ul, 0ul, CoverageMeasure::NonCumulative );
  }
  else {
    SetEnvForBranch( 0ul, 0ul, CoverageMeasure::NonCumulative );
    exit_sig = RunTracer( Tracer::Branch, opt, stdin );
  }
  const auto coverage_gain = ParseCoverage( coverage_log );
  const auto branch_trace = ReadBranchTrace( sink, opt, branch_log, try_val );
  RemoveFile( coverage_log );
  return std::make_tuple( exit_sig, coverage_gain, branch_trace );
}

std::tuple< Signal, CoverageGain, std::optional< BranchInfo > >
GetBranchInfo(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  const BigInt &try_val,
  const BranchPoint &targ_point
) {
  SetupFile( sink, seed );
  const auto stdin = PrepareStdIn( seed );
  const auto addr = std::uint64_t( targ_point.addr );
  const auto idx = std::uint32_t( targ_point.idx );
  Signal exit_sig;
  if( fork_server_on ) {
    exit_sig = RunBranchTracerForked( sink, opt, stdin, addr, idx, CoverageMeasure::Cumulative );
  }
  else {
    SetEnvForBranch( addr, idx, CoverageMeasure::Cumulative );
    exit_sig = RunTracer( Tracer::Branch, opt, stdin );
  }
  const auto coverage_gain = ParseCoverage( coverage_log );
  const auto branch_info_opt = TryReadBranchInfo( sink, opt, branch_log, try_val );
  return std::make_tuple( exit_sig, coverage_gain, branch_info_opt );
}

std::optional< BranchInfo > GetBranchInfoOnly(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  const BigInt &try_val,
  const BranchPoint &targ_point
) {
  SetupFile( sink, seed );
  const auto stdin = PrepareStdIn( seed );
  const auto addr = std::uint64_t( targ_point.addr );
  const auto idx = std::uint32_t( targ_point.idx );
  if( fork_server_on ) {
    RunBranchTracerForked( sink, opt, stdin, addr, idx, CoverageMeasure::Ignore );
  }
  else {
    SetEnvForBranch( addr, idx, CoverageMeasure::Ignore );
    RunTracer( Tracer::Branch, opt, stdin );
  }
  return TryReadBranchInfo( sink, opt, branch_log, try_val );
}

Signal NativeExecute(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed
) {
  SetupFile( sink, seed );
  const auto stdin = PrepareStdIn( seed );
  const auto timeout = opt.exec_timeout;
  auto r = Signal( exec( opt.native_raw_args.size(), const_cast< char** >( opt.native_raw_args.data() ), stdin.size(), reinterpret_cast< char* >( const_cast< std::byte* >( stdin.data() ) ), timeout ) );
  return r;
}

}
