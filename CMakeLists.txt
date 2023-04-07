cmake_minimum_required(VERSION 3.10)
set(
  CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/"
  ${CMAKE_MODULE_PATH}
)

set( PATTR_VERSION_MAJOR 0 )
set( PATTR_VERSION_MINOR 1 )
set( PATTR_VERSION_PATCH 0 )

PROJECT(fuzzuf
  VERSION ${PATTR_VERSION_MAJOR}.${PATTR_VERSION_MINOR}.${PATTR_VERSION_PATCH}
)

execute_process(
  COMMAND git rev-parse HEAD
  OUTPUT_VARIABLE PATTR_COMMIT
)
execute_process(
  COMMAND whoami
  OUTPUT_VARIABLE PATTR_USER
)
set( PATTR_BRANCH "unknown" CACHE STRING "The name of branch the package used" )
set( PATTR_VERSION_RELEASE 1 CACHE STRING "Release number of package" )
math( EXPR PATTR_VERSION_RELEASE_CALCULATED "${PATTR_VERSION_RELEASE}" )
set( PATTR_DESCRIPTION_SUMMARY "Extensible fuzzing framework" )
set( PATTR_HOMEPAGE_URL "https://github.com/fuzzuf/fuzzuf" )
set( PATTR_LICENSE "AGPL v3.0" )
set( PATTR_VENDOR "Ricerca Security" )
set( PATTR_DIST "ricsec" )
set( PATTR_MAINTAINER "Ricerca Security <fuzzuf-dev@ricsec.co.jp>" )
set( PATTR_COMPRESSIN_TYPE "xz" )

include(CheckIncludeFiles)
include(CheckCXXSourceCompiles)
include(GNUInstallDirs)
include(GetSubdirs)
include(AlgorithmEnabled)
find_package(PkgConfig)
enable_testing()
try_compile(
  HAS_CXX_STD_BIT
  ${CMAKE_BINARY_DIR}/check
  SOURCES ${CMAKE_SOURCE_DIR}/check/has_bit.cpp
)
try_compile(
  HAS_CXX_STD_FILESYSTEM
  ${CMAKE_BINARY_DIR}/check
  SOURCES ${CMAKE_SOURCE_DIR}/check/has_filesystem.cpp
)
if( HAS_CXX_STD_FILESYSTEM )
  find_package( Boost 1.53.0 COMPONENTS system unit_test_framework program_options REQUIRED )
else()
  find_package( Boost 1.53.0 COMPONENTS filesystem system unit_test_framework program_options REQUIRED )
endif()
get_subdirs( AVAILABLE_ALGORITHMS ${CMAKE_CURRENT_SOURCE_DIR}/include/fuzzuf/algorithms )
string(REPLACE ";" "," AVAILABLE_ALGORITHMS_STR "${AVAILABLE_ALGORITHMS}")
set( ENABLE_ALGORITHMS "all" CACHE STRING "Available values: ${AVAILABLE_ALGORITHMS_STR},all" )
string(REPLACE "," ";" ALGORITHMS "${ENABLE_ALGORITHMS}")
list(FIND ALGORITHMS "all" ALL_INDEX_IN_ALGORITHMS)
foreach( alg ${ALGORITHMS} )
  list(FIND AVAILABLE_ALGORITHMS ${alg} alg_index )
  if( "${alg_index}" EQUAL "-1" )
    if( NOT "${alg}" MATCHES "all" )
      message( FATAL_ERROR "Unknown algorithm : ${alg}" )
    endif()
  endif()
endforeach()
if( NOT "${ALL_INDEX_IN_ALGORITHMS}" EQUAL "-1" )
  set( ALGORITHMS "${AVAILABLE_ALGORITHMS}" )
endif()
message( "Enabled algorithms : ${ALGORITHMS}" )


set(CMAKE_VERBOSE_MAKEFILE OFF)

find_package( Threads REQUIRED )
find_package( Python3x REQUIRED )
find_package( Pybind11 REQUIRED )
if( ${CMAKE_VERSION} VERSION_LESS 3.17.0 )
  execute_process(
    COMMAND python3-config --extension-suffix
    OUTPUT_VARIABLE Python3_SOABI
  )
  string( REGEX REPLACE "^\\." "" Python3_SOABI "${Python3_SOABI}" )
  string( REGEX REPLACE "\\.(so|dylib|dll)\n$" "" Python3_SOABI "${Python3_SOABI}" )
elseif( "${Python3_SOABI}" STREQUAL "@SO@" )
  execute_process(
    COMMAND ${CMAKE_SOURCE_DIR}/check/get_soabi.py
    OUTPUT_VARIABLE Python3_SOABI
  )
endif()
option( ENABLE_DOXYGEN "generate documents" OFF )
if( ENABLE_DOXYGEN )
  find_package( Doxygen OPTIONAL_COMPONENTS dot mscgen dia )
endif()
option( ENABLE_FLC "enable flc" OFF )
if( ENABLE_FLC )
  pkg_check_modules( FLC flc REQUIRED )
else()
  set( FLC_FOUND FALSE )
endif()
find_package( NlohmannJSON REQUIRED )
pkg_check_modules( CRYPTOPP libcrypto++ )
if( NOT CRYPTOPP_FOUND )
  pkg_check_modules( CRYPTOPP libcryptopp REQUIRED )
endif()
find_package( Pin )
find_package( QEMU )
find_package( CoreSightTrace )
find_package( PTProxy )
find_package( FridaTrace )
# fuzz_toysはリチェルカセキュリティが内部で使用しているテスト用バイナリ群である
# Nezhaは類似した2つのPUTを必要としており、fuzz_toysにはその条件を満たす物が含まれている
find_package( FuzzToys )
find_package( FuzzToysSymCC )
find_package( AFL )
find_package( FuzzufCC )
find_package( SymCC )
if( ${CMAKE_VERSION} VERSION_GREATER_EQUAL 3.6.0 )
  option( ENABLE_CLANG_TIDY "enable clang-tidy" OFF )
  if( ENABLE_CLANG_TIDY )
    find_program( CLANG_TIDY clang-tidy REQUIRED )
    set( CLANG_TIDY_CONFIG "-checks=-*,boost-*,bugprone-*,cert-*,cppcoreguidelines-*,hicpp-*,modernize-*,performance-*,portability-*,readability-*,misc-*" )
    set( CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY} ${CLANG_TIDY_CONFIG} )
    set( CLANG_TIDY_CONFIG_FOR_TEST "${CLANG_TIDY_CONFIG},-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers,-cppcoreguidelines-macro-usage,-cert-err58-cpp,-cppcoreguidelines-avoid-non-const-global-variables,-cppcoreguidelines-pro-type-vararg,-hicpp-vararg,-hicpp-explicit-conversions,-cppcoreguidelines-macro-usage,-cppcoreguidelines-pro-type-cstyle-cast,-cppcoreguidelines-pro-type-member-init,-cppcoreguidelines-special-member-functions,-hicpp-explicit-conversions,-cppcoreguidelines-pro-type-vararg,-hicpp-vararg" )
  endif()
endif()

set( ADDITIONAL_COMPILE_FLAGS )
list(APPEND ADDITIONAL_COMPILE_FLAGS "-Werror" )
option( ENABLE_ADDRSAN "build with address sanitizer" OFF)
if( ENABLE_ADDRSAN )
  list(APPEND ADDITIONAL_COMPILE_FLAGS "-fsanitize=address" )
  list(APPEND ADDITIONAL_LINK_FLAGS "-fsanitize=address" )
  if( CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NOT ENABLE_CLANG_TIDY )
    list(APPEND ADDITIONAL_COMPILE_FLAGS "-static-libasan" )
    list(APPEND ADDITIONAL_LINK_FLAGS "-static-libasan" )
  endif()
endif()
option( ENABLE_PCOMPSAN "build with pointer compare sanitizer" OFF)
if( ENABLE_PCOMPSAN )
  list(APPEND ADDITIONAL_COMPILE_FLAGS "-fsanitize=pointer-compare" )
  list(APPEND ADDITIONAL_LINK_FLAGS "-fsanitize=pointer-compare" )
endif()
option( ENABLE_PSUBSAN "build with pointer subtract sanitizer" OFF)
if( ENABLE_PSUBSAN )
  list(APPEND ADDITIONAL_COMPILE_FLAGS "-fsanitize=pointer-subtract" )
  list(APPEND ADDITIONAL_LINK_FLAGS "-fsanitize=pointer-subtract" )
endif()
option( ENABLE_THREADSAN "build with thread sanitizer" OFF)
if( ENABLE_THREADSAN )
  list(APPEND ADDITIONAL_COMPILE_FLAGS "-fsanitize=thread" )
  list(APPEND ADDITIONAL_LINK_FLAGS "-fsanitize=thread" )
endif()
option( ENABLE_LEAKSAN "build with leak sanitizer" OFF)
if( ENABLE_LEAKSAN )
  list(APPEND ADDITIONAL_COMPILE_FLAGS "-fsanitize=leak" )
  list(APPEND ADDITIONAL_LINK_FLAGS "-fsanitize=leak" )
endif()
option( ENABLE_UBSAN "build with undefined behavior sanitizer" OFF)
if( ENABLE_UBSAN )
  list(APPEND ADDITIONAL_COMPILE_FLAGS "-fsanitize=undefined" )
  list(APPEND ADDITIONAL_LINK_FLAGS "-fsanitize=undefined" )
  if( CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NOT ENABLE_CLANG_TIDY )
    list(APPEND ADDITIONAL_COMPILE_FLAGS "-static-libubsan" )
    list(APPEND ADDITIONAL_LINK_FLAGS "-static-libubsan" )
  elseif( CMAKE_CXX_COMPILER_ID MATCHES "Clang" )
  endif()
endif()
if( CMAKE_CXX_COMPILER_ID MATCHES "Clang" )
  list(APPEND ADDITIONAL_COMPILER_FLAGS "-fsized-deallocation" )
endif()
option( ENABLE_CXX20 "build with -std=c++20" OFF)
if( ENABLE_CXX20 )
  set( CMAKE_CXX_STANDARD "20" )
else()
  set( CMAKE_CXX_STANDARD "17" )
endif()
option( ENABLE_DANGEROUS_STACK_TRACE_OUTPUT "print backtrace on SIGSEGV" ON )
if( CMAKE_CXX_COMPILER_ID STREQUAL "GNU" )
  if( CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 10.0 )
    option( ENABLE_STATIC_ANALYZER "enable static analyzer" OFF)
    if( ENABLE_STATIC_ANALYZER )
      list(APPEND ADDITIONAL_COMPILE_FLAGS "-fanalyzer")
    endif()
  endif()
endif()
option( ENABLE_DISPLAY_LAST_STACK_TRACE "parse and display stacktrace.dump at next execution" OFF )
option( ENABLE_HEAVY_TEST "enable heavy test" ON )
option( ENABLE_NODE_TRACER "enable node tracer" OFF )
option( ENABLE_NODE_TRACER_ADDRESS_DUMPER "display node address on DumpTrace outputs" OFF )
option( ENABLE_NODE_TRACER_LOCATION_DUMPER "display source filename and line number on DumpTrace outputs" OFF )
option( ENABLE_NODE_TRACER_TRANSPARENT_DUMPER "display transparent node on DumpTrace outputs" OFF )
set( DEFAULT_RUNLEVEL "Release" CACHE STRING "runlevel" )
string( TOUPPER "${DEFAULT_RUNLEVEL}" DEFAULT_RUNLEVEL_CAP )
set( RELEASE_MARCH "native" CACHE STRING "target cpu architecture")

string(REPLACE ";" " " ADDITIONAL_COMPILE_FLAGS_STR "${ADDITIONAL_COMPILE_FLAGS}")
string(REPLACE ";" " " ADDITIONAL_LINK_FLAGS_STR "${ADDITIONAL_LINK_FLAGS}")

set(ADDITIONAL_WARNING_FLAGS)
list( APPEND ADDITIONAL_WARNING_FLAGS "-Wall" )
list( APPEND ADDITIONAL_WARNING_FLAGS "-Wextra" )
if( CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR ENABLE_CLANG_TIDY )
  list( APPEND ADDITIONAL_WARNING_FLAGS "-Wno-unevaluated-expression" )
  list( APPEND ADDITIONAL_WARNING_FLAGS "-Wno-unneeded-internal-declaration" )
  list( APPEND ADDITIONAL_WARNING_FLAGS "-Wno-inconsistent-missing-override" )
  list( APPEND ADDITIONAL_WARNING_FLAGS "-Wno-unused-variable" )
  list( APPEND ADDITIONAL_WARNING_FLAGS "-fsized-deallocation" )
endif()
string(REPLACE ";" " " ADDITIONAL_WARNING_FLAGS_STR "${ADDITIONAL_WARNING_FLAGS}")

set(CMAKE_CXX_FLAGS_DEBUG "-g ${ADDITIONAL_WARNING_FLAGS_STR}")
set(CMAKE_C_FLAGS_DEBUG "-g ${ADDITIONAL_WARNING_FLAGS_STR}")
set(CMAKE_CXX_FLAGS_RELEASE "-march=${RELEASE_MARCH} -O3 ${ADDITIONAL_WARNING_FLAGS_STR}")
set(CMAKE_C_FLAGS_RELEASE "-march=${RELEASE_MARCH} -O3 ${ADDITIONAL_WARNING_FLAGS_STR}")

find_program(LSB_RELEASE_EXEC lsb_release)
if( NOT LSB_RELEASE_EXEC STREQUAL "LSB_RELEASE_EXEC-NOTFOUND" )
  execute_process(COMMAND ${LSB_RELEASE_EXEC} -is
    OUTPUT_VARIABLE LSB_RELEASE_ID_SHORT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
else()
  set( LSB_RELEASE_ID_SHORT "unknown" )
endif()

if( ${CMAKE_BUILD_TYPE} MATCHES Debug )
  set( DEFINE_DEBUG_ASSERT "Yes" )
endif()

configure_file(
  "${CMAKE_SOURCE_DIR}/check/config.h.in"
  "${CMAKE_BINARY_DIR}/config.h"
)

if( ${LSB_RELEASE_ID_SHORT} STREQUAL "Debian" )
  set( CPACK_GENERATOR "DEB" )
elseif( ${LSB_RELEASE_ID_SHORT} STREQUAL "Ubuntu" )
  set( CPACK_GENERATOR "DEB" )
elseif( ${LSB_RELEASE_ID_SHORT} STREQUAL "RedHatEnterpriseServer" )
  set( CPACK_GENERATOR "RPM" )
elseif( ${LSB_RELEASE_ID_SHORT} STREQUAL "Fedora" )
  set( CPACK_GENERATOR "RPM" )
elseif( ${LSB_RELEASE_ID_SHORT} STREQUAL "CentOS" )
  set( CPACK_GENERATOR "RPM" )
elseif( ${LSB_RELEASE_ID_SHORT} STREQUAL "AmazonAMI" )
  set( CPACK_GENERATOR "RPM" )
elseif( ${LSB_RELEASE_ID_SHORT} STREQUAL "openSUSE project" )
  set( CPACK_GENERATOR "RPM" )
elseif( ${LSB_RELEASE_ID_SHORT} STREQUAL "SUSE LINUX" )
  set( CPACK_GENERATOR "RPM" )
elseif( ${LSB_RELEASE_ID_SHORT} STREQUAL "Scientific" )
  set( CPACK_GENERATOR "RPM" )
else()
  set( CPACK_GENERATOR "TGZ" )
endif()

set( DEB_REQUIREMENTS )
set( RPM_REQUIREMENTS )

list(APPEND RPM_REQUIREMENTS "python3" )

if( "${PATTR_PYENV}" STREQUAL "native" )
  set( CPACK_PACKAGE_NAME "fuzzuf" )
else()
  set( CPACK_PACKAGE_NAME "fuzzuf_python_${PATTR_PYENV}" )
  set( CPACK_DEBIAN_PACKAGE_PROVIDES "fuzzuf" )
  set( CPACK_RPM_PACKAGE_PROVIDES "fuzzuf" )
  set( CPACK_DEBIAN_PACKAGE_CONFLICTS "fuzzuf" )
  set( CPACK_RPM_PACKAGE_CONFLICTS "fuzzuf" )
endif()
set( CPACK_PACKAGE_VENDOR "${PATTR_VENDOR}" )
set( CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE" )
set( CPACK_PACKAGE_VERSION_MAJOR "${PATTR_VERSION_MAJOR}" )
set( CPACK_PACKAGE_VERSION_MINOR "${PATTR_VERSION_MINOR}" )
set( CPACK_PACKAGE_VERSION_PATCH "${PATTR_VERSION_PATCH}" )
set( CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PATTR_DESCRIPTION_SUMMARY}" )
set( CPACK_PACKAGE_DESCRIPTION "Generated by: ${PATTR_USER}\nBranch: ${PATTR_BRANCH}\nCommit: ${PATTR_COMMIT}" )
set( CPACK_PACKAGE_HOMEPAGE_URL "${PATTR_HOMEPAGE_URL}" )
set( CPACK_STRIP_FILES FALSE )

set( CPACK_DEBIAN_PACKAGE_RELEASE "${PATTR_VERSION_RELEASE_CALCULATED}" )
set( CPACK_DEBIAN_FILE_NAME DEB-DEFAULT )
set( CPACK_DEBIAN_PACKAGE_MAINTAINER "${PATTR_MAINTAINER}" )
set( CPACK_DEBIAN_COMPRESSION_TYPE "${PATTR_COMPRESSION_TYPE}" )
set( CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON )
string(REPLACE ";" "," DEB_REQUIREMENTS_STR "${DEB_REQUIREMENTS}")
set( CPACK_DEBIAN_PACKAGE_DEPENDS "${DEB_REQUIREMENTS_STR}" )
message("deb requirements: ${DEB_REQUIREMENTS_STR}")

set( CPACK_RPM_PACKAGE_RELEASE "${PATTR_VERSION_RELEASE_CALCULATED}" )
set( CPACK_RPM_PACKAGE_RELEASE_DIST "${PATTR_DIST}" )
set( CPACK_RPM_PACKAGE_LICENSE "${PATTR_LICENSE}" )
set( CPACK_RPM_PACKAGE_URL "${PATTR_HOMEPAGE_URL}" )
set( CPACK_RPM_COMPRESSION_TYPE "${PATTR_COMPRESSION_TYPE}" )
string(REPLACE ";" "," RPM_REQUIREMENTS_STR "${RPM_REQUIREMENTS}")
set( CPACK_DEBIAN_PACKAGE_DEPENDS "${RPM_REQUIREMENTS_STR}" )
message("rpm requirements: ${RPM_REQUIREMENTS_STR}")

set(CPACK_SET_DESTDIR true)

include(CPack)

#アルファベット順に並べてください
set(
  FUZZUF_SOURCES
  channel/fd_channel.cpp
  exec_input/exec_input.cpp
  exec_input/exec_input_set.cpp
  exec_input/on_disk_exec_input.cpp
  exec_input/on_memory_exec_input.cpp
  executor/base_proxy_executor.cpp
  executor/executor.cpp
  executor/linux_fork_server_executor.cpp
  executor/native_linux_executor.cpp
  executor/pintool_executor.cpp
  executor/polytracker_executor.cpp
  executor/proxy_executor.cpp
  executor/qemu_executor.cpp
  feedback/borrowed_fd_feedback.cpp
  feedback/disposable_fd_feedback.cpp
  feedback/exit_status_feedback.cpp
  feedback/file_feedback.cpp
  feedback/inplace_memory_feedback.cpp
  feedback/persistent_memory_feedback.cpp
  feedback/put_exit_reason_type.cpp
  logger/logger.cpp
  logger/log_file_logger.cpp
  logger/stdout_logger.cpp
  optimizer/for_nlohmann_json.cpp
  optimizer/store.cpp
  optimizer/slopt/slopt_optimizer.cpp
  optimizer/slopt/thompson_sampling.cpp
  utils/check_crash_handling.cpp
  utils/check_if_string_is_decimal.cpp
  utils/common.cpp
  utils/count_regular_files.cpp
  utils/create_empty_file.cpp
  utils/errno_to_system_error.cpp
  utils/get_aligned_addr.cpp
  utils/get_external_seeds.cpp
  utils/get_hash.cpp
  utils/hex_dump.cpp
  utils/is_executable.cpp
  utils/load_inputs.cpp
  utils/map_file.cpp
  utils/sha1.cpp
  utils/to_hex.cpp
  utils/to_string.cpp
  utils/vfs/vfs.cpp
  utils/vfs/local_filesystem.cpp
  utils/which.cpp
  utils/workspace.cpp
  utils/zip_range.cpp
)

if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
  set(
    FUZZUF_SOURCES
    ${FUZZUF_SOURCES}
    executor/coresight_executor.cpp
  )
endif()

if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
  set(
    FUZZUF_SOURCES
    ${FUZZUF_SOURCES}
    executor/pt_executor.cpp
  )
endif()

add_library(
  fuzzuf_core
  SHARED
  ${FUZZUF_SOURCES}
)

set_target_properties(
  fuzzuf_core
  PROPERTIES
  VERSION ${PROJECT_VERSION_MINOR}
  SOVERSION ${PROJECT_VERSION_PATCH}
  SUFFIX "${PROJECT_VERSION_MAJOR}${CMAKE_SHARED_LIBRARY_SUFFIX}"
)

set( FUZZUF_CLI_ALGORITHM_SPECIFIC_SOURCES "" )
FOREACH( alg ${ALGORITHMS} )
  file(GLOB ALGORITHM_SOURCES LIST_DIRECTORIES false RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "${CMAKE_CURRENT_SOURCE_DIR}/cli/fuzzers/${alg}/*.cpp" )
  list(APPEND FUZZUF_CLI_ALGORITHM_SPECIFIC_SOURCES ${ALGORITHM_SOURCES} )
ENDFOREACH()

#アルファベット順に並べてください
set(
  FUZZUF_CLI_SOURCES
  cli/command_line_args.cpp
  cli/create_fuzzer_instance_from_argv.cpp
  cli/fuzzer_builder_register.cpp
  ${FUZZUF_CLI_ALGORITHM_SPECIFIC_SOURCES}
  cli/parse_global_options_for_fuzzer.cpp
  cli/setup_execution_environment.cpp
)

### CLI tool
add_executable(
  fuzzuf-cli
  cli/cli_entry_point.cpp
)
set_target_properties(fuzzuf-cli PROPERTIES OUTPUT_NAME "fuzzuf")

### Library of CLI for unit tests
add_library(
  fuzzuf-cli-lib
  SHARED
  ${FUZZUF_CLI_SOURCES}
)

set_target_properties(
  fuzzuf-cli-lib
  PROPERTIES
  VERSION ${PROJECT_VERSION_MINOR}
  SOVERSION ${PROJECT_VERSION_PATCH}
  SUFFIX "${PROJECT_VERSION_MAJOR}${CMAKE_SHARED_LIBRARY_SUFFIX}"
)


set( FUZZUF_LIBRARIES )
set( FUZZUF_INCLUDE_DIRS )
set( FUZZUF_LIBRARY_DIRS )

list(APPEND FUZZUF_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/include" )
list(APPEND FUZZUF_INCLUDE_DIRS "${CMAKE_BINARY_DIR}" )
list(APPEND FUZZUF_INCLUDE_DIRS "${Pybind11_INCLUDE_DIRS}" )
list(APPEND FUZZUF_INCLUDE_DIRS "${Python3_INCLUDE_DIRS}" )
list(APPEND FUZZUF_INCLUDE_DIRS "${NLOHMANN_JSON_INCLUDE_DIRS}" )
list(APPEND FUZZUF_LIBRARIES "${Python3_LIBRARIES}")
list(APPEND FUZZUF_LIBRARIES "${${CMAKE_DL_LIBS}}")
list(APPEND FUZZUF_LIBRARIES "${NLOHMANN_JSON_LIBRARIES}" )
if( ${CMAKE_VERSION} VERSION_LESS 3.15.0 )
  list(APPEND FUZZUF_INCLUDE_DIRS "${Boost_INCLUDE_DIRS}" )
else()
  list(APPEND FUZZUF_LIBRARIES Boost::headers )
endif()
if( NOT HAS_CXX_STD_FILESYSTEM )
  list(APPEND FUZZUF_LIBRARIES Boost::filesystem )
endif()
if( FLC_FOUND )
  list(APPEND FUZZUF_INCLUDE_DIRS "${FLC_INCLUDE_DIRS}" )
  list(APPEND FUZZUF_LIBRARY_DIRS "${FLC_LIBRARY_DIRS}" )
  list(APPEND FUZZUF_LIBRARIES "${FLC_LIBRARIES}")
endif()
list(APPEND FUZZUF_INCLUDE_DIRS "${CRYPTOPP_INCLUDE_DIRS}" )
list(APPEND FUZZUF_LIBRARY_DIRS "${CRYPTOPP_LIBRARY_DIRS}" )
list(APPEND FUZZUF_LIBRARIES "${CRYPTOPP_LIBRARIES}")
list(APPEND FUZZUF_LIBRARIES Boost::system )
list(APPEND FUZZUF_LIBRARIES Boost::program_options )
list(APPEND FUZZUF_LIBRARIES Threads::Threads )
list(APPEND FUZZUF_LIBRARIES ${CMAKE_DL_LIBS} )
list(APPEND FUZZUF_LIBRARIES util )

link_directories(
  ${FUZZUF_LIBRARY_DIRS}
)

add_subdirectory(algorithms)
algorithm_enabled( python_wrapper_enabled "${ALGORITHMS}" "python" )
if( python_wrapper_enabled )
  add_subdirectory(python)
endif()

### Configure dependencies
target_include_directories(
  fuzzuf_core
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
)

target_include_directories(
  fuzzuf-cli
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf-cli
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf-cli
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf-cli
  fuzzuf-cli-lib
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  ${FUZZUF_ALGORITHM_LIBS}
)

set_target_properties(
  fuzzuf-cli-lib
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf-cli-lib
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf-cli-lib
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  ${FUZZUF_ALGORITHM_LIBS}
)
target_include_directories(
  fuzzuf-cli-lib
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

install(
  TARGETS fuzzuf_core fuzzuf-cli fuzzuf-cli-lib
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
if( "${PATTR_PYENV}" STREQUAL "native" )
  if( DOXYGEN_FOUND )
    set(DOXYGEN_SOURCE_BROWSER YES)
    set(DOXYGEN_EXTRACT_PRIVATE YES)
    if( ${CMAKE_VERSION} VERSION_LESS 3.12.0 )
      file( GLOB_RECURSE FUZZUF_HEADERS RELATIVE ${CMAKE_SOURCE_DIR} "*.hpp" )
      doxygen_add_docs(
        fuzzuf_doc
        ${FUZZUF_SOURCES}
        ${FUZZUF_HEADERS}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
      )
    elseif( ${CMAKE_VERSION} VERSION_LESS 3.16.0 )
      doxygen_add_docs(
        fuzzuf_doc
        ALL
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
      )
    else()
      doxygen_add_docs(
        fuzzuf_doc
        ALL
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
      )
    endif()
    if( ${CMAKE_VERSION} VERSION_LESS 3.14.0 )
      install( DIRECTORY ${CMAKE_BINARY_DIR}/html DESTINATION ${CMAKE_INSTALL_DOCDIR} )
    else()
      install( DIRECTORY ${CMAKE_BINARY_DIR}/html TYPE DOC )
    endif()
  endif()
endif()

subdirs( test tools include )
