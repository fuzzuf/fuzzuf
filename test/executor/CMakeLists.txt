add_executable( test-nativelinux-run native_linux_run.cpp )
target_link_libraries(
  test-nativelinux-run
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-nativelinux-run
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-nativelinux-run
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-nativelinux-run
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-nativelinux-run
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "native_linux_executor.native_linux_context.run" COMMAND test-nativelinux-run )

add_executable( test-linuxforkserver-run linux_fork_server_run.cpp )
target_link_libraries(
  test-linuxforkserver-run
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-linuxforkserver-run
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-linuxforkserver-run
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-linuxforkserver-run
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-linuxforkserver-run
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "linux_fork_server_executor.run" COMMAND test-linuxforkserver-run )


add_executable( ok ok.cpp )
set_target_properties( ok PROPERTIES COMPILE_FLAGS "" )
add_executable( fail fail.cpp )
set_target_properties( fail PROPERTIES COMPILE_FLAGS "" )
add_executable( too_much_output too_much_output.cpp )
set_target_properties( too_much_output PROPERTIES COMPILE_FLAGS "" )
add_executable( never_exit never_exit.cpp )
set_target_properties( never_exit PROPERTIES COMPILE_FLAGS "" )
add_executable( abort abort.cpp )
set_target_properties( abort PROPERTIES COMPILE_FLAGS "" )
add_executable( segmentation_fault segmentation_fault.cpp )
set_target_properties( segmentation_fault PROPERTIES COMPILE_FLAGS "" )
add_executable( illegal_instruction illegal_instruction.cpp )
set_target_properties( illegal_instruction PROPERTIES COMPILE_FLAGS "" )
add_executable( print_env print_env.cpp )
set_target_properties( print_env PROPERTIES COMPILE_FLAGS "" )
add_executable( generate_outputs generate_outputs.cpp )
target_include_directories(
  generate_outputs
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)
target_link_libraries(
  generate_outputs
  ${FUZZUF_LIBRARIES}
)
set_target_properties( generate_outputs PROPERTIES COMPILE_FLAGS "" )

subdirs(
  non_fork_server_mode
  fork_server_mode
  proxy_executor
  qemu_executor
  coresight_executor
  pt_executor
)

if(PIN_FOUND)
add_executable( test-pintool-run pintool_run.cpp )
target_link_libraries(
  test-pintool-run
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-pintool-run
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-pintool-run
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-pintool-run
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-pintool-run
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "pintool_executor.pintool_context.run" COMMAND test-pintool-run )
endif()

add_executable( test-executor-ijon ijon.cpp )
target_link_libraries(
  test-executor-ijon
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-executor-ijon
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-executor-ijon
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-executor-ijon
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-executor-ijon
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( FUZZUF_CC_FOUND )
add_test( NAME "executor.ijon" COMMAND test-executor-ijon )
endif()

