#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/core/utils.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/seed_queue.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/test_case.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/sync.hpp>
#include <fuzzuf/algorithms/eclipser/gray_concolic/gray_concolic.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/scheduler.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/fuzz.hpp>

namespace fuzzuf::algorithm::eclipser {

namespace {

void PrintFoundSeed(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed
) {
  if( opt.verbosity >= 1 ) {
    std::string message = "[*] Found a new seed: ";
    message += seed.ToString();
    message += "\n";
    sink( std::move( message ) );
  }
}

std::optional< Priority >
EvalSeed(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  Signal exit_sig,
  CoverageGain cov_gain
) {
  test_case::Save( sink, opt, seed, exit_sig, cov_gain );
  if( cov_gain == CoverageGain::NewEdge ) {
    PrintFoundSeed( sink, opt, seed );
  }
  const auto is_abnormal = signal::IsTimeout( exit_sig ) || signal::IsCrash( exit_sig );
  if( is_abnormal ) {
    return std::nullopt;
  }
  else {
    return priority::OfCoverageGain( cov_gain );
  }
}

std::vector< std::pair< Priority, seed::Seed > >
MakeRelocatedItems(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const std::vector< std::tuple< seed::Seed, Signal, CoverageGain > > &seeds
) {
  std::vector< std::pair< Priority, seed::Seed > > temp;
  for( const auto &v: seeds ) {
    auto &[seed,exit_sig,cov_gain] = v;
    const auto priority_maybe = EvalSeed( sink, opt, seed, exit_sig, cov_gain );
    if( priority_maybe ) {
      const auto relocated = seed.RelocateCursor();
      std::transform(
        relocated.begin(),
        relocated.end(),
        std::back_inserter( temp ),
        [&]( const auto &v ) {
          return std::make_pair( *priority_maybe, v );
        }
      );
    }
  }
  return temp;
}

namespace {

std::optional< Priority >
MakeSteppedItems(
  Priority pr,
  seed::Seed &seed
) {
  const bool proceed_maybe = seed.ProceedCursorInplace();
  if( !proceed_maybe ) {
    return std::nullopt;
  }
  else {
    return pr;
  }
}

}

// Decides how to share the resource with AFL instances.
void ScheduleWithAFL(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt
) {
  if( opt.sync_dir != "" ) {
    scheduler::CheckAndReserveTime( sink, opt );
  }
}

// Sychronize the seed queue with AFL instances.
seed_queue::SeedQueue &SyncWithAFL(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  seed_queue::SeedQueue &seed_queue,
  int n
) {
  if( opt.sync_dir != "" && ( n & SYNC_N ) == 0 ) {
    return sync::Run( sink, opt, seed_queue );
  }
  else {
    return seed_queue;
  }
}

}

void FuzzOnce(
  const std::function<void(std::string &&)> &sink,
  std::mt19937 &rng,
  const options::FuzzOption &opt,
  seed_queue::SeedQueue &seed_queue,
  int &n
) {
  ScheduleWithAFL( sink, opt );
  SyncWithAFL( sink, opt, seed_queue, n );
  if( seed_queue.IsEmpty() ) {
    if( ( n % 10 ) == 0 && opt.verbosity >= 2 ) {
      sink( "Seed queue empty, waiting...\n" );
    }
    sleep( 1 );
  }
  else {
    auto [priority,seed] = seed_queue.DequeueInplace();
    if( opt.verbosity >= 2 ) {
      std::string message = "Fuzzing with: ";
      message += seed.ToString();
      message += "\n";
      sink( std::move( message ) );
    }
    auto new_items = gray_concolic::Run( sink, rng, opt, seed );
    auto relocated_items = MakeRelocatedItems( sink, opt, new_items );
    auto stepped_items_priority = MakeSteppedItems( priority, seed );
    for( auto &v: relocated_items ) {
      seed_queue.EnqueueInplace( v.first, std::move( v.second ) );
    }
    if( stepped_items_priority ) {
      seed_queue.EnqueueInplace( *stepped_items_priority, std::move( seed ) );
    }
  }
  ++n;
}

void FuzzUntilEmpty(
  const std::function<void(std::string &&)> &sink,
  std::mt19937 &rng,
  const options::FuzzOption &opt
) {
  seed_queue::SeedQueue seed_queue;
  seed_queue.EnqueueInplace( Priority::Normal, seed::Seed( opt.fuzz_source ) );
  int n = 0;
  while( !seed_queue.IsEmpty() && !Expired( opt.timelimit ) ) {
    FuzzOnce( sink, rng, opt, seed_queue, n );
  }
}


void FuzzLoop(
  const std::function<void(std::string &&)> &sink,
  std::mt19937 &rng,
  const options::FuzzOption &opt
) {
  seed_queue::SeedQueue seed_queue;
  seed_queue.EnqueueInplace( Priority::Normal, seed::Seed( opt.fuzz_source ) );
  int n = 0;
  while( !Expired( opt.timelimit ) ) {
    FuzzOnce( sink, rng, opt, seed_queue, n );
  }
}

}

