add_library(
  fuzzuf_core_eclipser
  STATIC
  core/typedef.cpp
  core/branch_info.cpp
  core/byte_val.cpp
  core/bytes_utils.cpp
  core/seed.cpp
  core/executor.cpp
  core/utils.cpp
  core/failwith.cpp
  core/libexec.c
  gray_concolic/linearity.cpp
  gray_concolic/linear_equation.cpp
  gray_concolic/linear_inequality.cpp
  gray_concolic/monotonicity.cpp
  gray_concolic/branch_trace.cpp
  gray_concolic/branch_tree.cpp
  gray_concolic/path_constraint.cpp
  gray_concolic/solve.cpp
  gray_concolic/gray_concolic.cpp
  fuzz/seed_queue.cpp
  fuzz/test_case.cpp
  fuzz/sync.cpp
  fuzz/scheduler.cpp
  fuzz/fuzz.cpp
  cli_compat/options.cpp
  cli_compat/fuzzer.cpp
)

target_include_directories(
  fuzzuf_core_eclipser
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_eclipser
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_eclipser
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_eclipser
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_eclipser
  ${FUZZUF_LIBRARIES}
)

subdirs(
  instrumentor
)
