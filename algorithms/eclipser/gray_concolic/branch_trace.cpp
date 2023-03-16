#include "fuzzuf/algorithms/eclipser/core/byte_val.hpp"
#include "fuzzuf/algorithms/eclipser/core/utils.hpp"
#include "fuzzuf/algorithms/eclipser/core/executor.hpp"
#include "fuzzuf/algorithms/eclipser/core/failwith.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/branch_trace.hpp"

namespace fuzzuf::algorithm::eclipser::gray_concolic {

namespace branch_trace {

std::pair< std::vector< std::vector< BranchInfo > >, std::vector< seed::Seed > >
CollectAux(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  const std::pair< std::vector< std::vector< BranchInfo > >, std::vector< seed::Seed > > &acc,
  const BigInt &try_val
) {
  const auto &[acc_traces, acc_candidates] = acc;
  const auto try_byte_val = byteval::Sampled{ std::byte( std::uint8_t( try_val ) ) };
  const auto try_seed = seed.UpdateCurByte( try_byte_val );
  const auto [exit_sig,cov_gain,trace] = executor::GetBranchTrace(
    sink, opt, try_seed, try_val
  );
  std::vector< std::vector< BranchInfo > > new_acc_traces;
  new_acc_traces.push_back( trace );
  new_acc_traces.insert(
    new_acc_traces.end(),
    acc_traces.begin(),
    acc_traces.end()
  );
  std::vector< seed::Seed > new_acc_candidates;
  if( cov_gain == CoverageGain::NewEdge || signal::IsCrash( exit_sig ) ) {
    new_acc_candidates.push_back( seed );
    new_acc_candidates.insert(
      new_acc_candidates.end(),
      acc_candidates.begin(),
      acc_candidates.end()
    );
  }
  else {
    new_acc_candidates = acc_candidates;
  }
  return std::make_pair( new_acc_traces, new_acc_candidates );
}

std::pair< std::vector< std::vector< BranchInfo > >, std::vector< seed::Seed > >
Collect(
  const std::function<void(std::string &&)> &sink,
  const seed::Seed &seed,
  const options::FuzzOption &opt,
  const BigInt &min_val,
  const BigInt &max_val
) {
  const auto n_spawn = opt.n_spawn;
  const auto try_vals = SampleInt( min_val, max_val, n_spawn );
  std::vector< std::vector< BranchInfo > > traces;
  std::vector< seed::Seed > candidates;
  for( const auto &try_val: try_vals ) {
    std::tie( traces, candidates ) = CollectAux(
      sink,
      opt,
      seed,
      std::make_pair(
        std::move( traces ),
        std::move( candidates )
      ),
      try_val
    );
  }
  std::reverse( traces.begin(), traces.end() );
  std::reverse( candidates.begin(), candidates.end() ); // To preserver order.
  return std::make_pair( traces, candidates );
} 

}

}

