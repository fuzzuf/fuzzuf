/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
/**
 * @file mask.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_MASK_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_MASK_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"
#include "fuzzuf/utils/type_traits/get_nth.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class StaticMask
 * @brief This node masks input using the mask defined at the node creation
 * Only masked elements of input are passed to child nodes.
 * This node is intended to limit range to mutate.
 * The node takes one path for input.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Mask Mask container type.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Mask, typename Path>
struct StaticMask {};
template <typename R, typename... Args, typename Mask, typename Path>
struct StaticMask<R(Args...), Mask, Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * All arguments are transfered to constructor of the mask
   */
  StaticMask(Mask &&m) : mask(std::move(m)) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticMask", enter)
    bool empty = true;
    Mask masked;
    Path()(
        [&](auto &&input) {
          if (!mask.empty()) {
            mutator::Mask(input, mask, masked);
            boost::swap(input, masked);
            empty = false;
          }
        },
        std::forward<Args>(args)...);
    if (this->CallSuccessors(std::forward<Args>(args)...)) {
      base_type::SetResponseValue(true);
      FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticMask", abort)
      return base_type::GoToParent();
    }
    Path()(
        [&](auto &&input) {
          if (!empty) {
            boost::swap(input, masked);
            mutator::Unmask(masked, mask, input);
          }
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticMask", leave)
    return base_type::GoToDefaultNext();
  }

 private:
  Mask mask;
};
namespace standard_order {
template <typename T>
using StaticMaskStdArgOrderT = decltype(T::input);
template <typename F, typename Mask, typename Ord>
using StaticMask = libfuzzer::StaticMask<F, Mask, StaticMaskStdArgOrderT<Ord>>;
}  // namespace standard_order

/**
 * @class DynamicMask
 * @brief This node masks input using the mask specified by the Path
 * Only masked elements of input are passed to child nodes.
 * This node is intended to limit range to mutate.
 * The node takes 2 paths for mask and input.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Mask Mask container type.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
struct DynamicMask {};
template <typename R, typename... Args, typename Path>
struct DynamicMask<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("DynamicMask", enter)
    using mask_t =
        utils::type_traits::RemoveCvrT<utils::struct_path::PointedTypeT<
            R(Args...), utils::type_traits::GetNthT<0u, Path>>>;
    bool empty = true;
    mask_t masked;
    Path()(
        [&](auto &&mask, auto &&input) {
          if (!mask.empty()) {
            mutator::Mask(input, mask, masked);
            boost::swap(input, masked);
            empty = false;
          }
        },
        std::forward<Args>(args)...);
    if (this->CallSuccessors(std::forward<Args>(args)...)) {
      base_type::SetResponseValue(true);
      FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("DynamicMask", abort)
      return base_type::GoToParent();
    }
    Path()(
        [&](auto &&mask, auto &&input) {
          if (!empty) {
            boost::swap(input, masked);
            mutator::Unmask(masked, mask, input);
          }
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("DynamicMask", leave)
    return base_type::GoToDefaultNext();
  }
};
namespace standard_order {
template <typename T>
using DynamicMaskStdArgOrderT = decltype(T::mask && T::input);
template <typename F, typename Ord>
using DynamicMask = libfuzzer::DynamicMask<F, DynamicMaskStdArgOrderT<Ord>>;
}  // namespace standard_order

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
