add_executable( test-mutator-mutator mutator.cpp )
target_link_libraries(
        test-mutator-mutator
        test-common
        fuzzuf_core
	fuzzuf_core_afl_common
        ${FUZZUF_LIBRARIES}
        Boost::unit_test_framework
)
target_include_directories(
        test-mutator-mutator
        PRIVATE
        ${FUZZUF_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-mutator-mutator
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-mutator-mutator
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-mutator-mutator
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "mutator.mutator" COMMAND test-mutator-mutator )

add_executable( test-mutator-havoc havoc.cpp )
target_link_libraries(
        test-mutator-havoc
        test-common
        fuzzuf_core
	fuzzuf_core_afl_common
        ${FUZZUF_LIBRARIES}
        Boost::unit_test_framework
)
target_include_directories(
        test-mutator-havoc
        PRIVATE
        ${FUZZUF_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-mutator-havoc
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-mutator-havoc
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-mutator-havoc
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "mutator.havoc" COMMAND test-mutator-havoc )
