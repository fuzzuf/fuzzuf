add_library(
  fuzzuf_core_nautilus
  STATIC
  fuzzer/fuzzer.cpp
  fuzzer/mutation_hierarflow_routines.cpp
  fuzzer/other_hierarflow_routines.cpp
  fuzzer/queue.cpp
  fuzzer/state.cpp
  fuzzer/update_hierarflow_routines.cpp
  grammartec/chunkstore.cpp
  grammartec/context.cpp
  grammartec/mutator.cpp
  grammartec/recursion_info.cpp
  grammartec/rule.cpp
  grammartec/tree.cpp
)

target_include_directories(
  fuzzuf_core_nautilus
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_nautilus
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_nautilus
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_nautilus
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_nautilus
  ${FUZZUF_LIBRARIES}
  fuzzuf_core
)


