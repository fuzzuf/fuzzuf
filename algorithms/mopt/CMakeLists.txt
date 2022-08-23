add_library(
  fuzzuf_core_mopt
  STATIC
  mopt_fuzzer.cpp
  mopt_hierarflow_routines.cpp
  mopt_optimizer.cpp
  mopt_state.cpp
  mopt_setting.cpp
  mopt_testcase.cpp
)

target_include_directories(
  fuzzuf_core_mopt
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_mopt
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_mopt
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_mopt
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_mopt
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_afl_common
)
