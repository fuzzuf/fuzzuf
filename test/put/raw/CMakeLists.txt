cmake_minimum_required(VERSION 3.10)
set(
  CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/"
  ${CMAKE_MODULE_PATH}
)

PROJECT(
  raw-targets
  LANGUAGES C CXX
)

set( CMAKE_C_FLAGS_DEBUG "-g -Wall -Wextra" )
set( CMAKE_C_FLAGS_RELEASE "-g -Wall -Wextra" )
set( CMAKE_CXX_FLAGS_DEBUG "-g -Wall -Wextra" )
set( CMAKE_CXX_FLAGS_RELEASE "-g -Wall -Wextra" )

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
  raw-sample
  sample.cpp
)

add_executable(
  raw-stdin
  stdin.c
)

add_executable(
  raw-linear
  linear.c
)

add_executable(
  raw-loop
  loop.c
)

add_executable(
  raw-monoton
  monoton.c
)

add_executable(
  raw-motiv
  motiv.c
)

add_executable(
  raw-nested
  nested.c
)

add_executable(
  raw-timeout
  timeout.c
)

add_executable(
  raw-length
  length.c
)

add_executable(
  raw-easy_to_branch
  ../afl_gcc/easy_to_branch.c 
)

add_executable(
  raw-threshold
  ../afl_gcc/threshold.c 
)

add_executable(
  raw-hard_to_branch
  ../afl_gcc/hard_to_branch.c 
)

add_executable(
  raw-no_branch
  ../afl_gcc/no_branch.c 
)

add_executable(
  raw-monotonic
  ../afl_gcc/monotonic.c 
)

