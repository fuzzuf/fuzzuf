add_executable( test-aflplusplus-loop loop.cpp )
target_link_libraries(
  test-aflplusplus-loop
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-aflplusplus-loop
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-aflplusplus-loop
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-aflplusplus-loop
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-aflplusplus-loop
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( ENABLE_HEAVY_TEST )
add_test( NAME "aflplusplus.loop" COMMAND test-aflplusplus-loop )
endif()

add_executable( test-aflplusplus-cli_parser cli_parser.cpp )
target_link_libraries(
  test-aflplusplus-cli_parser
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-aflplusplus-cli_parser
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-aflplusplus-cli_parser
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-aflplusplus-cli_parser
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-aflplusplus-cli_parser
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.aflplusplus.cli_parser" COMMAND test-aflplusplus-cli_parser )

add_executable( test-aflplusplus-compute_weight compute_weight.cpp )
target_link_libraries(
  test-aflplusplus-compute_weight
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-aflplusplus-compute_weight
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-aflplusplus-compute_weight
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-aflplusplus-compute_weight
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-aflplusplus-compute_weight
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.aflplusplus.compute_weight" COMMAND test-aflplusplus-compute_weight )

