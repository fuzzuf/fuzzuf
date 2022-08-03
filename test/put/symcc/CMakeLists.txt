cmake_minimum_required(VERSION 3.10)
set(
  CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/"
  ${CMAKE_MODULE_PATH}
)

PROJECT(
  symcc-targets
  LANGUAGES C CXX
)

set( CMAKE_C_COMPILER "${SYMCC_CC_PROXY}" )
set( CMAKE_C_FLAGS_DEBUG "-g -Wall -Wextra" )
set( CMAKE_C_FLAGS_RELEASE "-g -Wall -Wextra" )
set( CMAKE_CXX_COMPILER "${SYMCC_CXX_PROXY}" )
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
  symcc-sample
  sample.cpp
)

add_executable(
  symcc-easy_to_branch
  ../afl_gcc/easy_to_branch.c 
)

