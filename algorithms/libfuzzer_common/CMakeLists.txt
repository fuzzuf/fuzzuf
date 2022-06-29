add_library(
  fuzzuf_core_libfuzzer_common
  STATIC
  config.cpp
  dictionary.cpp
  fuzzer.cpp
  input_info.cpp
  options.cpp
  state.cpp
  test_utils.cpp
  trace.cpp
  utils.cpp
)

target_include_directories(
  fuzzuf_core_libfuzzer_common
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_libfuzzer_common
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_libfuzzer_common
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_libfuzzer_common
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_libfuzzer_common
  ${FUZZUF_LIBRARIES}
  fuzzuf_core
)


