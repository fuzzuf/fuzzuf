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

set( ADDITIONAL_COMPILE_FLAGS )
set( ADDITIONAL_LINK_FLAGS )
list( APPEND ADDITIONAL_LINK_FLAGS "-fsanitize=address" )
list( APPEND ADDITIONAL_LINK_FLAGS "-fsanitize-address-use-after-scope" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-fsized-deallocation" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-O2" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-fno-omit-frame-pointer" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-gline-tables-only" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-fsanitize=address" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-fsanitize-address-use-after-scope" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-Wall" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-Wextra" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "-flto" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "--bitmap-load-point=FullLinkTimeOptimizationLast" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "--cfg-exporter-load-point=FullLinkTimeOptimizationLast" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "--bitmap-instrumentation-method=NODE" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "--bb-id-assigner-id-generation-strategy=SEQUENTIAL" )
list( APPEND ADDITIONAL_COMPILE_FLAGS "--features=bb-id-assigner,bitmap-feedback,cfg-exporter,forkserver" )
string(REPLACE ";" " " ADDITIONAL_COMPILE_FLAGS_STR "${ADDITIONAL_COMPILE_FLAGS}")
string(REPLACE ";" " " ADDITIONAL_LINK_FLAGS_STR "${ADDITIONAL_LINK_FLAGS}")


set( CMAKE_C_COMPILER ${FUZZUF_CC_CC} )
set( CMAKE_CXX_COMPILER ${FUZZUF_CC_CXX} )
set( CMAKE_C_FLAGS_DEBUG "${ADDITIONAL_COMPILE_FLAGS_STR}" )
set( CMAKE_C_FLAGS_RELEASE "${ADDITIONAL_COMPILE_FLAGS_STR}" )
set( CMAKE_CXX_FLAGS_DEBUG "${ADDITIONAL_COMPILE_FLAGS_STR}" )
set( CMAKE_CXX_FLAGS_RELEASE "${ADDITIONAL_COMPILE_FLAGS_STR}" )

subdirs( harfbuzz )

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
  kscheduler-easy_to_branch
  easy_to_branch.c 
)

get_katz_centricity( kscheduler-easy_to_branch )

