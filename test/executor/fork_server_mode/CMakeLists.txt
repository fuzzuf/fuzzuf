add_executable( test-executor-run-fork run.cpp )
target_link_libraries(
  test-executor-run-fork
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-executor-run-fork
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-executor-run-fork
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-executor-run-fork
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_test( NAME "native_linux_executor.native_linux_context.fork.run" 
        COMMAND test-executor-run-fork )
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-executor-run-non-fork
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "native_linux_executor.native_linux_context.non-fork.run" 
          COMMAND test-executor-run-non-fork )

add_executable( test-executor-fork_server_mode-environment_variables environment_variables.cpp )
target_link_libraries(
  test-executor-fork_server_mode-environment_variables
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-executor-fork_server_mode-environment_variables
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-executor-fork_server_mode-environment_variables
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-executor-fork_server_mode-environment_variables
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-executor-fork_server_mode-environment_variables
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "executor.fork_server_mode.environment_variables"
          COMMAND test-executor-fork_server_mode-environment_variables )

add_executable( test-executor-fork_server_mode-output_dir output_dir.cpp )
target_link_libraries(
  test-executor-fork_server_mode-output_dir
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-executor-fork_server_mode-output_dir
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-executor-fork_server_mode-output_dir
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-executor-fork_server_mode-output_dir
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-executor-fork_server_mode-output_dir
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "executor.fork_server_mode.output_dir"
          COMMAND test-executor-fork_server_mode-output_dir )
