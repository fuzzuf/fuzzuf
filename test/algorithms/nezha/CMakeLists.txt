add_executable( test-algorithms-nezha-output_hash2 output_hash2.cpp )
target_link_libraries(
  test-algorithms-nezha-output_hash2
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-nezha-output_hash2
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-nezha-output_hash2
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-nezha-output_hash2
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-nezha-output_hash2
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( FUZZTOYS_FOUND )
add_test( NAME "algorithms.nezha.output_hash2" COMMAND test-algorithms-nezha-output_hash2 )
endif()
add_executable( test-algorithms-nezha-output_hash3 output_hash3.cpp )
target_link_libraries(
  test-algorithms-nezha-output_hash3
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-nezha-output_hash3
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-nezha-output_hash3
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-nezha-output_hash3
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-nezha-output_hash3
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( FUZZTOYS_FOUND )
add_test( NAME "algorithms.nezha.output_hash3" COMMAND test-algorithms-nezha-output_hash3 )
endif()

