#include <boost/mpl/at.hpp>
#include <boost/mpl/int.hpp>
#include <nlohmann/json.hpp>
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/algorithms/eclipser/core/utils.hpp"
#include "fuzzuf/algorithms/eclipser/core/config.hpp"
#include "fuzzuf/algorithms/eclipser/core/failwith.hpp"
#include "fuzzuf/algorithms/eclipser/core/group_by.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/branch_tree.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/branch_trace.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/linear_equation.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/linear_inequality.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/monotonicity.hpp"

namespace fuzzuf::algorithm::eclipser::gray_concolic {

void to_json( nlohmann::json &dest, const Condition &src ) {
  dest = std::visit(
    [i=src.index()]( const auto &v ) {
      auto root = nlohmann::json( v );
      root[ "type" ] = i;
      return root;
    },
    src
  );
}
void from_json( const nlohmann::json &src, Condition &dest ) {
  dest = Condition();
  if( src.find( "type" ) != src.end() ) {
    if( src[ "type" ] == 0 ) {
      dest = LinEq( src );
    }
    else if( src[ "type" ] == 1 ) {
      dest = LinIneq( src );
    }
    else if( src[ "type" ] == 2 ) {
      dest = Mono( src );
    }
  }
}
void to_json( nlohmann::json &dest, const BranchCondition &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "branch_condition";
  dest[ "inspect" ] = src.first;
  dest[ "targ_pt" ] = src.second;
}
void from_json( const nlohmann::json &src, BranchCondition &dest ) {
  dest = BranchCondition();
  if( src.find( "inspect" ) != src.end() ) {
    dest.first = src[ "inspect" ];
  }
  if( src.find( "targ_pt" ) != src.end() ) {
    dest.second = src[ "targ_pt" ];
  }
}
void to_json( nlohmann::json &dest, const BranchSeq &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "branch_seq";
  dest[ "length" ] = src.length;
  dest[ "branches" ] = nlohmann::json::array();
  for( const auto &b: src.branches ) {
    auto temp = nlohmann::json::array();
    temp.push_back(
      nlohmann::json( b.first )
    );
    temp.push_back(
      nlohmann::json( b.second )
    );
    dest[ "branches" ].push_back( std::move( temp ) );
  }
}
void from_json( const nlohmann::json &src, BranchSeq &dest ) {
  dest = BranchSeq();
  if( src.find( "lenght" ) != src.end() ) {
    dest.length = src[ "length" ];
  }
  if( src.find( "branches" ) != src.end() ) {
    for( const auto &b: src[ "branches" ] ) {
      dest.branches.push_back(
        std::make_pair(
          BranchCondition( b[ 0 ] ),
          DistanceSign( b[ 1 ] )
        )
      );
    }
  }
}
void to_json( nlohmann::json &dest, const BranchTree &src ) {
  dest = nlohmann::json::object();
  if( src.which() == 0u ) {
    const auto &v = boost::get< Straight >( src );
    dest = v;
  }
  else if( src.which() == 1u ) {
    using type = boost::mpl::at< BranchTree::types, boost::mpl::int_< 1 > >::type;
    const auto &v = ForkedTree( boost::get< type >( src ) );
    dest = v;
  }
  else if( src.which() == 2u ) {
    using type = boost::mpl::at< BranchTree::types, boost::mpl::int_< 2 > >::type;
    const auto &v = DivergeTree( boost::get< type >( src ) );
    dest = v;
  }
}
void from_json( const nlohmann::json &src, BranchTree &dest ) {
  if( src.is_object() ) {
    dest = Straight( src );
  }
  else if( src.is_array() ) {
    if( src.size() == 3 ) {
      dest = ForkedTree( src );
    }
    else if( src.size() == 2 ) {
      dest = DivergeTree( src );
    }
  }
}
void to_json( nlohmann::json &dest, const ForkedTree &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "forked";
  dest[ "branch_seq" ] = std::get< 0 >( src );
  dest[ "branch_condition" ] = std::get< 1 >( src );
  dest[ "child_trees" ] = nlohmann::json::array();
  for( const auto &c: std::get< 2 >( src ) ) {
    auto temp = nlohmann::json::object();
    temp[ "sign" ] = std::get< 0 >( c );
    temp[ "next" ] = std::get< 1 >( c );
    dest[ "child_trees" ].push_back( std::move( temp ) );
  }
}
void from_json( const nlohmann::json &src, ForkedTree &dest ) {
  std::vector< std::pair< DistanceSign, BranchTree > > temp;
  for( const auto &c: src[ "child_trees" ] ) {
    BranchTree child;
    from_json( c[ "next" ], child );
    temp.push_back(
      std::pair< DistanceSign, BranchTree >(
        DistanceSign( c[ "sign" ] ),
        std::move( child )
      )
    );
  }
  dest = ForkedTree{
    BranchSeq( src[ "branch_seq" ] ),
    BranchCondition( src[ "branch_condition" ] ),
    std::move( temp )
  };
}
void to_json( nlohmann::json &dest, const DivergeTree &src ) {
  dest = nlohmann::json::object();
  dest[ "type" ] = "diverge_tree";
  dest[ "branch_seq" ] = std::get< 0 >( src );
  dest[ "sub_trees" ] = nlohmann::json::array();
  for( const auto &c: std::get< 1 >( src ) ) {
    auto temp = nlohmann::json::array();
    dest[ "sub_trees" ].push_back( c );
  }
}
void from_json( const nlohmann::json &src, DivergeTree &dest ) {
  std::vector< BranchTree > temp;
  for( const auto &c: src[ "sub_trees" ] ) {
    BranchTree child;
    from_json( c, child );
    temp.push_back( std::move( child ) );
  }
  dest = DivergeTree{
    BranchSeq( src[ "branch_seq" ] ),
    std::move( temp )
  };
}



namespace branch_seq {

BranchSeq empty() {
  return BranchSeq { 0, {} };
}

BranchSeq &Append(
  BranchSeq &branch_seq,
  const std::optional< BranchCondition > &branch_cond_opt,
  DistanceSign dist_sign
) {
  if( !branch_cond_opt ) {
    return branch_seq;
  }
  ++branch_seq.length;
  branch_seq.branches.insert(
    branch_seq.branches.begin(),
    std::pair< BranchCondition, DistanceSign >(
      *branch_cond_opt,
      dist_sign
    )
  );
  return branch_seq;
}

}

namespace branch_tree {

BrTraceList GenCombAux(
  const BrTraceList &acc_combs,
  const std::vector< BranchInfo > &window_elems,
  const std::vector< BranchInfo >::const_iterator &left_elems_begin,
  const std::vector< BranchInfo >::const_iterator &left_elems_end,
  std::size_t n
) {
  if( left_elems_begin == left_elems_end ) {
    return acc_combs;
  }
  const auto &head_elem = *left_elems_begin;
  auto new_combs = Combination(
    n - 1u,
    window_elems.begin(),
    window_elems.end()
  ); // Select 'n-1' from window elements
  for( auto &elems: new_combs ) {
    elems.push_back( head_elem );
  } // Use 'headElem' as 'n'th
  auto new_window_elems = std::vector< BranchInfo >(
    window_elems.empty() ?
    window_elems.begin() :
    std::next( window_elems.begin() ),
    window_elems.end()
  );
  new_window_elems.push_back( head_elem );
  auto temp = acc_combs;
  temp.insert(
    temp.end(),
    new_combs.begin(),
    new_combs.end()
  );
  return GenCombAux(
    temp,
    new_window_elems,
    std::next( left_elems_begin ),
    left_elems_end,
    n
  );
}

BrTraceList
GenComb(
  const std::vector< BranchInfo >::const_iterator &elems_begin,
  const std::vector< BranchInfo >::const_iterator &elems_end,
  std::size_t window_size,
  std::size_t n
) {
  if( std::size_t( std::distance( elems_begin, elems_end ) ) < window_size ) {
    return Combination( n, elems_begin, elems_end );
  }
  else {
    const auto [head_elems,tail_elems] = SplitList( window_size, elems_begin, elems_end );
    const auto initial_combs = Combination( n, head_elems );
    const auto initial_window = std::vector< BranchInfo >(
      head_elems.empty() ?
      head_elems.begin() :
      std::next( head_elems.begin() ),
      head_elems.end()
    );
    return GenCombAux(
      initial_combs,
      initial_window,
      tail_elems.begin(),
      tail_elems.end(),
      n
    );
  }
}

  /// Check if provided BranchInfos are valid target to infer linearity or
  /// monotonicity. Note that we can skip inference if all the branch distances
  /// are the same.
bool CheckValidTarget(
  const std::vector< BranchInfo >::const_iterator &br_infos_begin,
  const std::vector< BranchInfo >::const_iterator &br_infos_end
) {
  if( std::distance( br_infos_begin, br_infos_end ) < 3 ) {
    return false;
  }
  else {
    const auto &br_info = *br_infos_begin;
    return std::find_if(
      std::next( br_infos_begin ),
      br_infos_end,
      [&br_info]( const auto &f ) {
        return f.distance != br_info.distance;
      }
    ) != br_infos_end;
  }
}

std::optional< LinEq >
InferLinEqAux(
  const Context &ctx,
  const BrTraceList::const_iterator &br_info_combinations_begin,
  const BrTraceList::const_iterator &br_info_combinations_end
) {
  if( br_info_combinations_begin == br_info_combinations_end ) {
    return std::nullopt;
  }
  const auto br_info_triple = *br_info_combinations_begin;
  const auto lin_eq_opt = linear_equation::Find( ctx, br_info_triple );
  if( lin_eq_opt ) {
    return lin_eq_opt;
  }
  else {
    return InferLinEqAux(
      ctx,
      std::next( br_info_combinations_begin ),
      br_info_combinations_end
    );
  }
}

std::optional< LinEq > InferLinEq(
  const Context &ctx,
  const std::vector< BranchInfo >::const_iterator &br_infos_begin,
  const std::vector< BranchInfo >::const_iterator &br_infos_end
) {
  if( CheckValidTarget( br_infos_begin, br_infos_end ) ) {
    const auto comb = GenComb( br_infos_begin, br_infos_end, BRANCH_COMB_WINDOW, 3 ); // XXX
    return InferLinEqAux( ctx, comb.begin(), comb.end() );
  }
  else {
    return std::nullopt;
  }
}

std::optional< LinIneq >
InferLinIneqAux(
  const Context &ctx,
  const BrTraceList::const_iterator &br_info_combinations_begin,
  const BrTraceList::const_iterator &br_info_combinations_end
) {
  if( br_info_combinations_begin == br_info_combinations_end ) {
    return std::nullopt;
  }
  else {
    const auto br_info_triple = *br_info_combinations_begin;
    const auto lin_eq_opt = linear_inequality::Find( ctx, br_info_triple );
    if( lin_eq_opt ) {
      return lin_eq_opt;
    }
    else {
      return InferLinIneqAux(
        ctx,
        std::next( br_info_combinations_begin ),
        br_info_combinations_end
      );
    }
  }
}

std::optional< LinIneq >
InferLinIneq(
 const Context &ctx,
 const std::vector< BranchInfo >::const_iterator &br_infos_begin,
 const std::vector< BranchInfo >::const_iterator &br_infos_end
) {
  if( CheckValidTarget( br_infos_begin, br_infos_end ) ) {
    const auto comb = GenComb( br_infos_begin, br_infos_end, BRANCH_COMB_WINDOW, 3 ); // XXX
    return InferLinIneqAux( ctx, comb.begin(), comb.end() );
  }
  else {
    return std::nullopt;
  }
}

std::optional< Mono >
InferMonotonicity(
  const std::vector< BranchInfo >::const_iterator &br_infos_begin,
  const std::vector< BranchInfo >::const_iterator &br_infos_end
) {
  if( CheckValidTarget( br_infos_begin, br_infos_end ) ) {
    return monotonicity::Find( br_infos_begin, br_infos_end );
  }
  else {
    return std::nullopt;
  }
}


std::optional< BranchCondition >
InspectBranchInfos(
  const options::FuzzOption &/*opt*/,
  const Context &ctx,
  const VisitCntMap &visit_cnt_map,
  const std::vector< BranchInfo > &branch_infos
) {
    /// We already filtered out cases where length of BranchInfo is less than 3
  const auto &first_br_info = *branch_infos.begin();
  const auto targ_addr = first_br_info.inst_addr;
  const auto targ_idx = visit_cnt_map.find( targ_addr );
  const auto targ_pt = BranchPoint{ targ_addr, int( targ_idx->second ) };
  const auto branch_type = first_br_info.branch_type;
  if( branch_type == CompareType::Equality ) {
    const auto lin_eq = InferLinEq(
      ctx,
      branch_infos.begin(),
      branch_infos.end()
    );
    if( lin_eq ) {
      return BranchCondition{ LinEq( *lin_eq ), targ_pt };
    }
    else {
      const auto mono_opt = InferMonotonicity(
        branch_infos.begin(),
        branch_infos.end()
      );
      if( mono_opt ) {
        return BranchCondition{ Mono( *mono_opt ), targ_pt };
      }
      else {
        return std::nullopt;
      }
    }
  }
  else {
    const auto lin_ineq = InferLinIneq(
      ctx,
      branch_infos.begin(),
      branch_infos.end()
    );
    if( lin_ineq ) {
      return BranchCondition{ LinIneq( *lin_ineq ), targ_pt };
    }
    else {
      return std::nullopt;
    }
  }
}

Sign DecideSign( const BigInt &x ) {
  if( x > 0 ) {
    return Sign::Positive;
  }
  else if( x == 0 ) {
    return Sign::Zero;
  }
  else {
    return Sign::Negative;
  }
}

bool HaveSameAddr( const std::vector< BranchInfo > &br_infos ) {
  if( br_infos.empty() ) {
    return true;
  }
  else {
    const auto inst_addr = br_infos.begin()->inst_addr;
    return std::find_if(
      std::next( br_infos.begin() ),
      br_infos.end(),
      [inst_addr]( const auto &br ) {
        return br.inst_addr != inst_addr;
      }
    ) == br_infos.end();
  }
}

bool HaveSameBranchDistanceSign(
  const std::vector< BranchInfo >::const_iterator &br_infos_begin,
  const std::vector< BranchInfo >::const_iterator &br_infos_end
) {
  if( br_infos_begin == br_infos_end ) {
    return true;
  }
  const auto dist_sign = DecideSign( br_infos_begin->distance );
  return std::find_if(
    br_infos_begin,
    br_infos_end,
    [dist_sign]( const auto &br ) {
      return DecideSign( br.distance ) != dist_sign;
    }
  ) == br_infos_end;
}

  // Precondition : The first branchInfo of each branch trace should have the
  // same instuction address. Empty branch trace is not allowed.
std::tuple< VisitCntMap, BrTraceViewList, BranchSeq >
ExtractStraightSeq(
  const options::FuzzOption &opt,
  const Context &ctx,
  VisitCntMap &visit_cnt_map,
  BrTraceViewList &br_trace_view_list,
  BranchSeq &acc_branch_seq
) {
  while( true ) {
    if( br_trace_view_list.size() < 3u ) {
      failwith( "Unreachable" );
      return std::tuple< VisitCntMap, BrTraceViewList, BranchSeq >(); // unreachable
    }
    // Split each BranchTrace into a tuple of its head and tail.
    std::vector< BranchInfo > head_br_infos;
    std::transform(
      br_trace_view_list.begin(),
      br_trace_view_list.end(),
      std::back_inserter( head_br_infos ),
      []( const auto &v ) {
        return *v.begin();
      }
    );
    if( !HaveSameAddr( head_br_infos ) ) {
      failwith( "Unreachable" );
      return std::tuple< VisitCntMap, BrTraceViewList, BranchSeq >(); // unreachable
    }
    auto old_br_trace_view_list = br_trace_view_list;
    for( auto &b: br_trace_view_list ) {
      b = boost::iterator_range< std::vector< BranchInfo >::const_iterator >(
        std::next( b.begin() ),
        b.end()
      );
    }
    // Leave branch traces which are not empty.
    br_trace_view_list.erase(
      std::remove_if(
        br_trace_view_list.begin(),
        br_trace_view_list.end(),
        []( const auto &v ) {
          return v.empty();
        }
      ),
      br_trace_view_list.end()
    );
    {
      std::vector< BranchInfo > next_br_infos;
      std::transform(
        br_trace_view_list.begin(),
        br_trace_view_list.end(),
        std::back_inserter( next_br_infos ),
        []( const auto &v ) {
          return *v.begin();
        }
      );
      // Now examine the next address and decide whether to continue extracting.
      if(
        next_br_infos.size() >= 2 &&
        !HaveSameAddr( next_br_infos )
      ) {
      // Pass 'brTraceList', instead of 'tailBrTraces' since we need information
      // about the branch distance of previous branch before forking.
        br_trace_view_list = old_br_trace_view_list;
        return std::make_tuple(
          visit_cnt_map,
          br_trace_view_list,
          acc_branch_seq
        );
      }
    }
    if( head_br_infos.size() == 0u ) {
      throw exceptions::invalid_argument( "head_br_infos.size() == 0u", __FILE__, __LINE__ );
    }
    old_br_trace_view_list.clear();
    old_br_trace_view_list.shrink_to_fit();
    const auto &br_info = *head_br_infos.begin();
    const auto addr = br_info.inst_addr;
    auto cnt = visit_cnt_map.find( addr );
    if( cnt == visit_cnt_map.end() ) {
      cnt = visit_cnt_map.emplace( addr, 1u ).first;
    }
    else {
      cnt->second += 1u;
    }
    const auto br_cond_opt = InspectBranchInfos(
      opt,
      ctx,
      visit_cnt_map,
      head_br_infos
    );
    const auto dist_sign = DecideSign( br_info.distance );
    branch_seq::Append(
      acc_branch_seq,
      br_cond_opt,
      dist_sign
    );
    // Stop proceeding if no more than three branch traces are left./br_trace_view_list.size
    if( br_trace_view_list.size() < 3u ) {
      return std::make_tuple(
        visit_cnt_map,
        BrTraceViewList{},
        acc_branch_seq
      );
    }
  }
}

namespace {

BranchTree
BuildDivergeTree(
  const options::FuzzOption &opt,
  const Context &ctx,
  const VisitCntMap &visit_cnt_map,
  const BranchSeq &branch_seq,
  const BrTraceViewList &br_trace_list
) {
    // Now leave branch traces longer than 1, and group by its next InstAddr.
  auto new_br_trace_list = br_trace_list;
  new_br_trace_list.erase(
    std::remove_if(
      new_br_trace_list.begin(),
      new_br_trace_list.end(),
      []( const auto &v ) {
        return !branch_trace::IsLongerThanOne()( v );
      }
    ),
    new_br_trace_list.end()
  );
  auto grouped_traces = GroupBy(
    branch_trace::GetNextAddr(),
    new_br_trace_list
  );
  for( auto iter = grouped_traces.begin(); iter != grouped_traces.end(); ) {
    if( iter->second.size() < 3u ) {
      iter = grouped_traces.erase( iter );
    }
    else {
      ++iter;
    }
  }
  std::vector< BranchTree > sub_trees;
  std::transform(
    grouped_traces.begin(),
    grouped_traces.end(),
    std::back_inserter( sub_trees ),
    [&]( auto &v ) {
      return MakeAux( opt, ctx, visit_cnt_map, v.second );
    }
  );
  if( sub_trees.empty() ) {
    BranchTree v = branch_seq;
    return v;
  }
  else {
    return BranchTree{ DivergeTree( branch_seq, sub_trees ) };
  }
}

/*BranchTree
BuildForkTree(
  const options::FuzzOption &opt,
  const Context &ctx,
  const VisitCntMap &visit_cnt_map,
  const BranchSeq &branch_seq,
  const BranchCondition &branch_cond,
  const BrTraceList &br_trace_list
) {
  auto new_br_trace_list = br_trace_list;
  new_br_trace_list.erase(
    std::remove_if(
      new_br_trace_list.begin(),
      new_br_trace_list.end(),
      []( const auto &v ) {
        return !IsLongerThanOne( v );
      }
    )
  );
  const auto grouped_traces = GroupBy(
    &branch_trace::IsLongerThanOne,
    new_br_trace_list
  );
  std::vector< std::pair< Sign, BranchTree > > child_trees;
  std::transform(
    grouped_traces.begin(),
    grouped_traces.end(),
    std::back_inserter( child_trees ),
    [&]( const auto &v ) {
      const auto &branch_trace = *v.second.begin();
      const auto dist_sign = DecideSign( branch_trace.begin()->distance );
      BrTraceList tail_br_trace_list(
        std::next( v.second.begin() ),
        v.second.end()
      );
      const auto sub_tree =
        ( tail_br_trace_list.size() >= 3 ) ?
        MakeAux( opt, ctx, visit_cnt_map, tail_br_trace_list ) :
        Straight{ branch_seq::empty() };
      return std::make_pair( dist_sign, std::move( sub_tree ) );
    }
  );
  return ForkedTree{ branch_seq, branch_cond, std::move( child_trees ) };
}*/

}

/*BranchTree
BuiildDivergeTree(
  const options::FuzzOption &opt,
  const Context &ctx,
  const VisitCntMap &visit_cnt_map,
  const BranchSeq &branch_seq,
  const BrTraceList &br_trace_list
) {
  BrTraceList new_br_trace_list;
  new_br_trace_list.reserve( br_trace_list.size() );
  std::copy_if(
    br_trace_list.begin(),
    br_trace_list.end(),
    std::back_inserter( new_br_trace_list ),
    []( const auto &v ) {
      return branch_trace::IsLongerThanOne()( v );
    }
  );
  BrInfoCombinations grouped_traces;
  grouped_traces.reserve( new_br_trace_list.size() );
  for( const auto &group: GroupBy(
    branch_trace::GetNextAddr(),
    new_br_trace_list
  ) ) {
    if( group.second.size() >= 3u ) {
      grouped_traces.push_back( group.second );
    }
  }
  std::vector< BranchTree > sub_trees;
  sub_trees.reserve( grouped_traces.size() );
  for( const auto &v : grouped_traces ) {
    sub_trees.push_back( MakeAux( opt, ctx, visit_cnt_map, v ) );
  }
  if( sub_trees.empty() ) {
    return Straight{ branch_seq };
  }
  else {
    return DivergeTree{ branch_seq, sub_trees };
  }
}*/

BranchTree
BuildForkTree(
  const options::FuzzOption &opt,
  const Context &ctx,
  const VisitCntMap &visit_cnt_map,
  const BranchSeq &branch_seq,
  const BranchCondition &branch_cond,
  const BrTraceViewList &br_trace_list
) {
    // Now leave branch traces longer than 1, and group by its next InstAddr.
  BrTraceViewList new_br_trace_list;
  new_br_trace_list.reserve( br_trace_list.size() );
  std::copy_if(
    br_trace_list.begin(),
    br_trace_list.end(),
    std::back_inserter( new_br_trace_list ),
    []( const auto &v ) {
      return branch_trace::IsLongerThanOne()( v );
    }
  );
    // Defer filtering group with no more than three traces.
  std::vector< BrTraceViewList > grouped_traces;
  grouped_traces.reserve( new_br_trace_list.size() );
  for( const auto &group: GroupBy(
    branch_trace::GetNextAddr(),
    new_br_trace_list
  ) ) {
    if( group.second.size() >= 3u ) {
      grouped_traces.push_back( group.second );
    }
  }
  std::vector< std::pair< DistanceSign, BranchTree > > child_trees;
  child_trees.reserve( grouped_traces.size() );
  std::transform(
    grouped_traces.begin(),
    grouped_traces.end(),
    std::back_inserter( child_trees ),
    [&]( auto &br_trace_group ) {
      const auto &branch_trace = *br_trace_group.begin();
      const auto dist_sign = DecideSign( branch_trace.begin()->distance );
      for( auto &b: br_trace_group ) {
        b = boost::iterator_range< std::vector< BranchInfo >::const_iterator >(
          std::next( b.begin() ),
          b.end()
        );
      }
      BranchTree sub_tree;
      if( br_trace_group.size() >= 3 ) {
        sub_tree = MakeAux( opt, ctx, visit_cnt_map, br_trace_group );
      }
      else {
        sub_tree = Straight{ branch_seq::empty() };
      }
      return std::make_pair( dist_sign, sub_tree );
    }
  );
  return ForkedTree{ branch_seq, branch_cond, child_trees };
}

  // Precondition : The first branchInfo of each branch trace should have the
  // same instuction address. Empty branch trace is not allowed.
BranchTree
MakeAux(
  const options::FuzzOption &opt,
  const Context &ctx,
  const VisitCntMap &visit_cnt_map,
  BrTraceViewList &br_trace_view_list
) {
  auto acc_branch_seq = branch_seq::empty();
  auto new_visit_cnt_map_ = visit_cnt_map;
  auto [new_visit_cnt_map,new_br_trace_list,branch_seq] =
    ExtractStraightSeq(
      opt,
      ctx,
      new_visit_cnt_map_,
      br_trace_view_list,
      acc_branch_seq
    );
    // If there are no more branch trace to parse, construct 'Straight' tree.
  if( new_br_trace_list.empty() ) {
    return Straight{ branch_seq };
  }
  else {
      // At this point, the first branches info of branch traces have the same
      // instruction address, and diverge/forks at the next branch.
    std::vector< BranchInfo > head_br_infos;
    std::transform(
      br_trace_view_list.begin(),
      br_trace_view_list.end(),
      std::back_inserter( head_br_infos ),
      []( const auto &v ) {
        return *v.begin();
      }
    );
    if( !HaveSameAddr( head_br_infos ) ) {
      failwith( "Unreachable" );
      return BranchTree(); // unreachable
    }
      // First, fetch the head branch info and infer the branch condition.
    const auto &br_info = *head_br_infos.begin();
    const auto addr = br_info.inst_addr;
    auto cnt = new_visit_cnt_map.find( addr );
    if( cnt == new_visit_cnt_map.end() ) {
      cnt = new_visit_cnt_map.emplace( addr, 1u ).first;
    }
    else {
      cnt->second += 1u;
    }
    const auto branch_cond_opt = InspectBranchInfos(
      opt,
      ctx,
      new_visit_cnt_map,
      head_br_infos
    );
    if( !branch_cond_opt ) { // If failed to infer branch condition, handle as a 'diverge'
      return BuildDivergeTree(
        opt,
        ctx,
        new_visit_cnt_map,
        branch_seq,
        new_br_trace_list
      );
    }
    else {
      if( HaveSameBranchDistanceSign( new_br_trace_list.begin()->begin(), new_br_trace_list.begin()->end() ) ) {
          // Fork actually did not occur at this branch condition. Therefore,
          // append this branch to BranchSeq, and handle as a DivergeTree case.
        const auto &br_trace = *new_br_trace_list.begin();
        const auto dist_sign = DecideSign( br_trace.begin()->distance );
        branch_seq = branch_seq::Append( branch_seq, branch_cond_opt, dist_sign );
        return BuildDivergeTree(
          opt,
          ctx,
          new_visit_cnt_map,
          branch_seq,
          new_br_trace_list
        );
      }
      else {
        return BuildForkTree(
          opt,
          ctx,
          new_visit_cnt_map,
          branch_seq,
          *branch_cond_opt,
          new_br_trace_list
        );
      }
    }
  }
}

BranchTree
Make(
  const options::FuzzOption &opt,
  const Context &ctx,
  const BrTraceList &br_trace_list
) {
  BrTraceList new_br_trace_list = br_trace_list;
  new_br_trace_list.erase(
    std::remove_if(
      new_br_trace_list.begin(),
      new_br_trace_list.end(),
      []( const auto &v ) {
        return v.empty();
      }
    ),
    new_br_trace_list.end()
  );
  BrTraceViewList br_trace_view_list;
  br_trace_view_list.reserve( new_br_trace_list.size() );
  std::transform(
    new_br_trace_list.begin(),
    new_br_trace_list.end(),
    std::back_inserter( br_trace_view_list ),
    []( const auto &v ) {
      return boost::iterator_range< std::vector< BranchInfo >::const_iterator >(
        v.begin(),
        v.end()
      );
    }
  );
  std::vector< BrTraceViewList > grouped_traces;
  for( const auto &group: GroupBy(
    branch_trace::GetHeadAddr(),
    br_trace_view_list
  ) ) {
    if( group.second.size() >= 3u ) {
      grouped_traces.push_back( group.second );
    }
  }
  std::vector< BranchTree > sub_trees;
  sub_trees.reserve( grouped_traces.size() );
  for( auto &v : grouped_traces ) {
    sub_trees.push_back( MakeAux( opt, ctx, VisitCntMap{}, v ) );
  }
  if( sub_trees.size() == 1u ) {
    return sub_trees[ 0 ];
  }
  else {
    return DivergeTree{ branch_seq::empty(), sub_trees };
  }
}

int SizeOf( const BranchTree &branch_tree ) {
  return boost::apply_visitor(
    []( const auto &v ) -> int {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Straight > ) {
        return v.length;
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, DivergeTree > ) {
        const auto &branch_seq = std::get< 0 >( v );
        const auto &sub_tree = std::get< 1 >( v );
        return std::accumulate(
          sub_tree.begin(),
          sub_tree.end(),
          branch_seq.length,
          []( auto sum, const auto &v ) {
           return sum + SizeOf( v );
          }
        );
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, ForkedTree > ) {
      // Let us not count the branch itself at the fork point.
        const auto &branch_seq = std::get< 0 >( v );
        const auto &child_tree = std::get< 2 >( v );
        return std::accumulate(
          child_tree.begin(),
          child_tree.end(),
          branch_seq.length,
          []( auto sum, const auto &v ) {
           return sum + SizeOf( v.second );
          }
        );
      }
      else {
        return 0;
      }
    },
    branch_tree
  );
}

BranchTree Reverse( const BranchTree &branch_tree ) {
  return boost::apply_visitor(
    []( const auto &v ) -> BranchTree {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Straight > ) {
        const auto &branch_seq = v;
        return Straight{ BranchSeq{
          branch_seq.length,
          std::vector< std::pair< BranchCondition, DistanceSign > >(
            branch_seq.branches.rbegin(),
            branch_seq.branches.rend()
          )
        } };
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, DivergeTree > ) {
        const auto &branch_seq = std::get< 0 >( v );
        const auto &sub_trees = std::get< 1 >( v );
        auto new_branch_seq = BranchSeq{
          branch_seq.length,
          std::vector< std::pair< BranchCondition, DistanceSign > >(
            branch_seq.branches.rbegin(),
            branch_seq.branches.rend()
          )
        };
        std::vector< BranchTree > new_sub_trees;
        new_sub_trees.reserve( sub_trees.size() );
        std::transform(
          sub_trees.begin(),
          sub_trees.end(),
          std::back_inserter( new_sub_trees ),
          Reverse
        );
        return DivergeTree{
          std::move( new_branch_seq ),
          std::move( new_sub_trees )
        };
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, ForkedTree > ) {
        const auto &branch_seq = std::get< 0 >( v );
        const auto &br_cond = std::get< 1 >( v );
        const auto &child_trees = std::get< 2 >( v );
        auto new_branch_seq = BranchSeq{
          branch_seq.length,
          std::vector< std::pair< BranchCondition, DistanceSign > >(
            branch_seq.branches.rbegin(),
            branch_seq.branches.rend()
          )
        };
        std::vector< std::pair< DistanceSign, BranchTree > > new_child_trees;
        new_child_trees.reserve( child_trees.size() );
        std::transform(
          child_trees.begin(),
          child_trees.end(),
          std::back_inserter( new_child_trees ),
          []( const auto &v ) {
            return std::make_pair(
              v.first,
              Reverse( v.second )
            );
          }
        );
        return ForkedTree{
          std::move( new_branch_seq ),
          br_cond,
          std::move( new_child_trees )
        };
      }
    },
    branch_tree
  );
}
  
std::pair< std::vector< std::pair< BranchCondition, DistanceSign > >, int >
FilterBranchSeqAux(
  const SelectSet &select_set,
  int counter,
  const std::vector< std::pair< BranchCondition, DistanceSign > >::const_iterator &branches_begin,
  const std::vector< std::pair< BranchCondition, DistanceSign > >::const_iterator &branches_end,
  const std::pair< std::vector< std::pair< BranchCondition, DistanceSign > >, int > &acc_list
) {
  const auto &[acc_brs,acc_len] = acc_list;
  if( branches_begin == branches_end ) {
    return acc_list;
  }
  const auto &head_branch = *branches_begin;
  std::pair< std::vector< std::pair< BranchCondition, DistanceSign > >, int > new_acc_list;
  if( select_set.find( counter ) != select_set.end() ) {
    std::vector< std::pair< BranchCondition, DistanceSign > > new_acc_brs;
    new_acc_brs.push_back( head_branch );
    new_acc_brs.insert(
      new_acc_brs.end(),
      acc_brs.begin(),
      acc_brs.end()
    );
    new_acc_list = std::make_pair(
      std::move( new_acc_brs ),
      acc_len + 1
    );
  }
  else {
    new_acc_list = acc_list;
  }
  return FilterBranchSeqAux(
    select_set,
    counter + 1,
    std::next( branches_begin ),
    branches_end,
    new_acc_list
  );
}

std::pair< int, BranchSeq >
FilterBranchSeq(
  const SelectSet &select_set,
  int counter,
  const BranchSeq &branch_seq
) {
  const auto &branches = branch_seq.branches;
  auto [new_brs,new_len] = FilterBranchSeqAux(
    select_set,
    counter,
    branches.begin(),
    branches.end(),
    std::make_pair( std::vector< std::pair< BranchCondition, DistanceSign > >{}, 0 )
  );
  const auto new_counter = counter + branch_seq.length;
  auto new_branch_seq = branch_seq;
  new_branch_seq.branches = std::move( new_brs );
  new_branch_seq.length = new_len;
  return std::make_pair( new_counter, std::move( new_branch_seq ) );
}

std::pair< int, BranchTree >
FilterAndReverseAux(
  const SelectSet &select_set,
  int counter,
  const BranchTree &branch_trace
) {
  return boost::apply_visitor(
    [&]( const auto &v ) -> std::pair< int, BranchTree > {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Straight > ) {
        const auto [new_counter,new_branch_seq] = FilterBranchSeq( select_set, counter, v );
        return std::make_pair( new_counter, BranchTree( Straight( std::move( new_branch_seq ) ) ) );
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, DivergeTree > ) {
        const auto &branch_seq = std::get< 0 >( v );
        const auto &sub_trees = std::get< 1 >( v );
        auto [new_counter,new_branch_seq] = FilterBranchSeq( select_set, counter, branch_seq );
        std::vector< BranchTree > acc_sub_trees;
        for( const auto &sub_tree: sub_trees ) {
          auto [next_counter,next_sub_tree] = FilterAndReverseAux( select_set, new_counter, sub_tree );
          new_counter = next_counter;
          acc_sub_trees.insert(
            acc_sub_trees.begin(),
            next_sub_tree
          );
        }
        std::reverse( acc_sub_trees.begin(), acc_sub_trees.end() );
        return std::make_pair(
          new_counter,
          BranchTree( DivergeTree{
            std::move( new_branch_seq ),
            std::move( acc_sub_trees )
          } )
        );
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, ForkedTree > ) {
        const auto &branch_seq = std::get< 0 >( v );
        const auto &br_cond = std::get< 1 >( v );
        const auto &child_trees = std::get< 2 >( v );
        auto [new_counter,new_branch_seq] = FilterBranchSeq( select_set, counter, branch_seq );
        std::vector< std::pair< DistanceSign, BranchTree > > acc_child_trees;
        for( const auto &child_tree: child_trees ) {
          auto [next_counter,next_child_tree] = FilterAndReverseAux( select_set, new_counter, child_tree.second );
          new_counter = next_counter;
          acc_child_trees.insert(
            acc_child_trees.begin(),
            std::make_pair( child_tree.first, next_child_tree )
          );
        }
        return std::make_pair(
          new_counter,
          BranchTree( ForkedTree{
            std::move( new_branch_seq ),
            br_cond,
            std::move( acc_child_trees )
          } )
        );
      }
    },
    branch_trace
  );
}

BranchTree
FilterAndReverse(
  const SelectSet &select_set,
  const BranchTree &branch_tree
) {
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
  const auto [_,filtered_branch_tree] = FilterAndReverseAux( select_set, 0, branch_tree );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
  return filtered_branch_tree;
}

BranchTree
SelectAndRepair(
  std::mt19937 &rng,
  const options::FuzzOption &opt,
  const BranchTree &branch_tree
) {
  const auto select_n = opt.n_solve;
  const auto size = SizeOf( branch_tree );
  if( select_n > size ) {
    return Reverse( branch_tree );
  }
  else {
    const auto select_set = RandomSubset( rng, size, select_n );
    return FilterAndReverse( select_set, branch_tree );
  }
}

}

}

