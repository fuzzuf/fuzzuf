add_library(
  fuzzuf_core_die
  STATIC
  die_fuzzer.cpp
  die_hierarflow_routines.cpp
  die_state.cpp
)

target_include_directories(
  fuzzuf_core_die
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_die
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_die
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_die
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_die
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_afl_common
)


