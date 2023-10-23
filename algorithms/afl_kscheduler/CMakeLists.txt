add_library(
  fuzzuf_core_afl_kscheduler
  STATIC
  fuzzer.cpp
)

target_include_directories(
  fuzzuf_core_afl_kscheduler
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_afl_kscheduler
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_afl_kscheduler
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_afl_kscheduler
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_afl_kscheduler
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_afl_common
)

