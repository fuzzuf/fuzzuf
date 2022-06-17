cmake_minimum_required(VERSION 3.10)
set(
  CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/"
  ${CMAKE_MODULE_PATH}
)

PROJECT(
  fuzzuf-cc-targets
  LANGUAGES C
)

set(CMAKE_C_COMPILER afl-gcc)
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
  afl-empty
  empty.c 
)

