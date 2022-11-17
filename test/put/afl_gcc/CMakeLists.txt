cmake_minimum_required(VERSION 3.10)
set(
  CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/"
  ${CMAKE_MODULE_PATH}
)

PROJECT(
  afl-gcc-targets
  LANGUAGES CXX C
)

set(CMAKE_C_COMPILER ${AFL_CC})
set( CMAKE_C_FLAGS_DEBUG "-g -Wall -Wextra" )
set( CMAKE_C_FLAGS_RELEASE "-g -Wall -Wextra" )

execute_process(
  COMMAND git rev-parse HEAD
  OUTPUT_VARIABLE PATTR_COMMIT
)

execute_process(
  COMMAND whoami
  OUTPUT_VARIABLE PATTR_USER
)

include(CheckIncludeFiles)
include(CheckCXXSourceCompiles)
include(GNUInstallDirs)
find_package(PkgConfig)
enable_testing()

add_executable(
  afl_gcc-test_instr
  test-instr.c 
)

set_target_properties(
  afl_gcc-test_instr
  PROPERTIES
  OUTPUT_NAME
  "test-instr"
)

add_executable(
  afl_gcc-easy_to_branch
  easy_to_branch.c 
)

