#include <string>
#include <charconv>
#include <utility>
#include <chrono>
#include <thread>
#include <fuzzuf/algorithms/eclipser/core/executor.hpp>
#include <fuzzuf/algorithms/eclipser/core/config.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/test_case.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/scheduler.hpp>

namespace fuzzuf::algorithm::eclipser::scheduler {

namespace {
std::chrono::high_resolution_clock::time_point timer;
// Tentative efficiency of random fuzzing. TODO: Communicate with AFL for this.
constexpr float RAND_FUZZ_EFFICIENCY = 0.0005f;
// Decides sleep factor 'f', which will be used to sleep for 'f * elapsed time'.
// This means we will utilize 1 / (2 * (f + 1)) of the system resource.
float DecideSleepFactor(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  int round_execs,
  int round_tcs
) {
  const auto grey_conc_efficiency = float( round_tcs ) / float( round_execs );
  if( opt.verbosity >= 1 ) {
    std::string message = "[*] Efficiency = ";
    /*
    char temp[ 9 ] = { 0 };
    const auto result = std::to_chars( temp, std::next( temp, 8 ), grey_conc_efficiency, std::chars_format::fixed, 4 );
    if( result.ec == std::errc{} ) {
      message += temp;
    }
    else {*/
      message += std::to_string( grey_conc_efficiency );
    /*}*/
    sink( std::move( message ) );
  }
  // GREY_CONC_EFF : RAND_FUZZ_EFF = 1 : 2 * factor + 1
  const auto factor = ( grey_conc_efficiency == 0.0f ) ?
    SLEEP_FACTOR_MAX :
    ( RAND_FUZZ_EFFICIENCY / grey_conc_efficiency - 1.0f ) / 2.0f;
  // Bound the factor between minimum and maximum value allowed.
  return std::max( SLEEP_FACTOR_MIN, std::min( SLEEP_FACTOR_MAX, factor ) );
}
}

void Initialize() {
  executor::EnableRoundStatistics();
  test_case::EnableRoundStatistics();
  timer = std::chrono::high_resolution_clock::now();
}

// Check the efficiency of the system and sleep for a while to adjust the weight
// of resource use with AFL.
void CheckAndReserveTime(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt
) {
  const auto round_execs = executor::GetRoundExecs();
  if( round_execs > ROUND_SIZE ) {
    const auto round_tcs = test_case::GetRoundTestCaseCount();
    executor::ResetRoundExecs();
    test_case::ResetRoundTestCaseCount();
    const auto sleep_factor = DecideSleepFactor( sink, opt, round_execs, round_tcs );
    const auto round_elapsed = std::chrono::duration_cast< std::chrono::milliseconds >(
      std::chrono::high_resolution_clock::now() - timer
    ).count();
    const auto sleep_time = int( float( round_elapsed ) * sleep_factor );
    if( opt.verbosity >= 1 ) {
      std::string message = "[*] Elapsed round time: ";
      message += std::to_string( int( round_elapsed / 1000 ) );
      message += " sec.\n[*] Decided sleep time: ";
      message += std::to_string( int( sleep_time / 1000 ) );
      message += " sec.\n";
      sink( std::move( message ) );
    }
    std::this_thread::sleep_for( std::chrono::milliseconds( sleep_time ) );
    timer = std::chrono::high_resolution_clock::now();
  }
}

}

