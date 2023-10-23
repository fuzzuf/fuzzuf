#include <fuzzuf/utils/kscheduler/gen_dyn_weight.hpp>

namespace fuzzuf::utils::kscheduler {

GenDynWeight::GenDynWeight(
  const fs::path &script_path,
  const fs::path &nk_path
) {
  auto env = boost::this_process::environment();
  env[ "PYTHONPATH" ] = nk_path.c_str();
  child.reset( new boost::process::child(
    boost::process::search_path( "python3" ),
    script_path.c_str(),
    env
  ) );
}

GenDynWeight::~GenDynWeight() {
  child->terminate();
  child.reset();
}

}

