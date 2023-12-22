add_executable( test-afl_kscheduler-cli cli.cpp )
target_link_libraries(
  test-afl_kscheduler-cli
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-afl_kscheduler-cli
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-afl_kscheduler-cli
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-afl_kscheduler-cli
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-afl_kscheduler-cli
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( FUZZUF_CC_FOUND AND RAGEL_FOUND )
if( ENABLE_HEAVY_TEST )
add_test( NAME "algorithms.afl_kscheduler.cli" COMMAND test-afl_kscheduler-cli )
endif()
endif()

add_executable( test-afl_kscheduler-noksched noksched.cpp )
target_link_libraries(
  test-afl_kscheduler-noksched
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-afl_kscheduler-noksched
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-afl_kscheduler-noksched
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-afl_kscheduler-noksched
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-afl_kscheduler-noksched
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( FUZZUF_CC_FOUND AND RAGEL_FOUND )
if( ENABLE_HEAVY_TEST )
add_test( NAME "algorithms.afl_kscheduler.noksched" COMMAND test-afl_kscheduler-noksched )
endif()
endif()

add_executable( test-afl_kscheduler-cli_fork cli_fork.cpp )
target_link_libraries(
  test-afl_kscheduler-cli_fork
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-afl_kscheduler-cli_fork
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-afl_kscheduler-cli_fork
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-afl_kscheduler-cli_fork
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-afl_kscheduler-cli_fork
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( FUZZUF_CC_FOUND AND RAGEL_FOUND )
if( ENABLE_HEAVY_TEST )
add_test( NAME "algorithms.afl_kscheduler.cli_fork" COMMAND test-afl_kscheduler-cli_fork )
endif()
endif()

add_executable( test-afl_kscheduler-noksched_fork noksched_fork.cpp )
target_link_libraries(
  test-afl_kscheduler-noksched_fork
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-afl_kscheduler-noksched_fork
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-afl_kscheduler-noksched_fork
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-afl_kscheduler-noksched_fork
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-afl_kscheduler-noksched_fork
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( FUZZUF_CC_FOUND AND RAGEL_FOUND )
if( ENABLE_HEAVY_TEST )
add_test( NAME "algorithms.afl_kscheduler.noksched_fork" COMMAND test-afl_kscheduler-noksched_fork )
endif()
endif()





