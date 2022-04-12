add_executable( test-aflfast-loop loop.cpp )
target_link_libraries(
  test-aflfast-loop
  test-common
  fuzzuf
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-aflfast-loop
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-aflfast-loop
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-aflfast-loop
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-aflfast-loop
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( ENABLE_HEAVY_TEST )
add_test( NAME "aflfast.loop" COMMAND test-aflfast-loop )
endif()
