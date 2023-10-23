add_library(
  fuzzuf_core_rezzuf_kscheduler
  STATIC
  fuzzer.cpp
  state.cpp
  select_seed.cpp
  load_seed_if_needed.cpp
  apply_rand_muts.cpp
  havoc.cpp
  splicing.cpp
  abandon_entry.cpp
)

target_include_directories(
  fuzzuf_core_rezzuf_kscheduler
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_rezzuf_kscheduler
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_rezzuf_kscheduler
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_rezzuf_kscheduler
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_rezzuf_kscheduler
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_rezzuf
  fuzzuf_core_afl_common
)
