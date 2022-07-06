add_library( test-common SHARED random_data.cpp create_file.cpp move_to_program_location.cpp)

target_link_libraries(
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  ${FUZZUF_ALGORITHM_LIBS}
)

target_include_directories(
  test-common
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)
set_target_properties(
  test-common
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-common
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
