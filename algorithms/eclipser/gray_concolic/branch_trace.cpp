#include "fuzzuf/algorithms/eclipser/core/byte_val.hpp"
#include "fuzzuf/algorithms/eclipser/core/utils.hpp"
#include "fuzzuf/algorithms/eclipser/core/executor.hpp"
#include "fuzzuf/algorithms/eclipser/core/failwith.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/branch_trace.hpp"

namespace fuzzuf::algorithm::eclipser::gray_concolic {

namespace branch_trace {

namespace {
void CollectAux(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  std::vector< std::vector< BranchInfo > > &acc_traces,
  std::vector< seed::Seed > acc_candidates,
  const BigInt &try_val
) {
  const auto try_byte_val = byteval::Sampled{ std::byte( std::uint8_t( try_val ) ) };
  const auto try_seed = seed.UpdateCurByte( try_byte_val );
  const auto [exit_sig,cov_gain,trace] = executor::GetBranchTrace(
    sink, opt, try_seed, try_val
  );
  std::vector< std::vector< BranchInfo > > new_acc_traces;
  acc_traces.push_back( trace );
  std::vector< seed::Seed > new_acc_candidates;
  if( cov_gain == CoverageGain::NewEdge || signal::IsCrash( exit_sig ) ) {
    acc_candidates.push_back( seed );
  }
}
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
  traces.reserve( try_vals.size() );
  candidates.reserve( try_vals.size() );
  for( const auto &try_val: try_vals ) {
    CollectAux(
      sink,
      opt,
      seed,
      traces,
      candidates,
      try_val
    );
  }
  return std::make_pair( traces, candidates );
} 

}

}

