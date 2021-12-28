add_executable( test-algorithms-afl-dictionary dictionary.cpp )
target_link_libraries(
  test-algorithms-afl-dictionary
  test-common
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-afl-dictionary
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-afl-dictionary
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-afl-dictionary
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-afl-dictionary
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.afl.dictionary" COMMAND test-algorithms-afl-dictionary )

add_executable( test-afl-loop loop.cpp )
target_link_libraries(
  test-afl-loop
  test-common
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-afl-loop
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-afl-loop
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-afl-loop
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-afl-loop
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( ENABLE_HEAVY_TEST )
add_test( NAME "afl.loop" COMMAND test-afl-loop )
endif()
