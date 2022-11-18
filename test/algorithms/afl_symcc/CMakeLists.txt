add_executable( test-symcc-cli cli.cpp )
target_link_libraries(
  test-symcc-cli
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-symcc-cli
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-symcc-cli
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-symcc-cli
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-symcc-cli
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( AFL_FOUND AND SYMCC_FOUND )
add_test( NAME "algorithms.symcc.cli" COMMAND test-symcc-cli )
endif()

add_executable( test-symcc-parallel parallel.cpp )
target_link_libraries(
  test-symcc-parallel
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-symcc-parallel
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-symcc-parallel
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-symcc-parallel
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-symcc-parallel
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( AFL_FOUND AND SYMCC_FOUND )
add_test( NAME "algorithms.symcc.parallel" COMMAND test-symcc-parallel )
endif()
