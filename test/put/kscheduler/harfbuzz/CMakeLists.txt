include(CheckIncludeFiles)
include(CheckCXXSourceCompiles)
include(GNUInstallDirs)
find_package(PkgConfig)

pkg_check_modules( ICU icu-uc )

if( RAGEL_FOUND )

set( FUZZUF_HARFBUZZ_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/harfbuzz/ )
if( ${CMAKE_VERSION} VERSION_LESS 3.14.0 )
ExternalProject_Add(
  kscheduler-harfbuzz-dummy
  DOWNLOAD_COMMAND ""
  SOURCE_DIR ${FUZZUF_HARFBUZZ_SOURCE_DIR}
  CONFIGURE_COMMAND
    "<SOURCE_DIR>/autogen.sh"
    "--prefix=<INSTALL_DIR>"
    "--enable-static"
    "--disable-shared"
    "--with-glib=no"
    "--with-cairo=no"
  BUILD_COMMAND "echo"
  INSTALL_COMMAND "echo"
  LOG_CONFIGURE TRUE
  LOG_BUILD TRUE
  LOG_INSTALL TRUE
)
else()
ExternalProject_Add(
  kscheduler-harfbuzz-dummy
  DOWNLOAD_COMMAND ""
  SOURCE_DIR ${FUZZUF_HARFBUZZ_SOURCE_DIR}
  CONFIGURE_COMMAND
    "<SOURCE_DIR>/autogen.sh"
    "--prefix=<INSTALL_DIR>"
    "--enable-static"
    "--disable-shared"
    "--with-glib=no"
    "--with-cairo=no"
  BUILD_COMMAND "echo"
  INSTALL_COMMAND "echo"
  LOG_PATCH TRUE
  LOG_CONFIGURE TRUE
  LOG_BUILD TRUE
  LOG_INSTALL TRUE
  LOG_OUTPUT_ON_FAILURE TRUE
)
endif()

add_custom_target(
  kscheduler-harfbuzz-hb-buffer-deserialize-json.hh
  COMMAND ragel -e -F1 -o ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-buffer-deserialize-json.hh ${CMAKE_CURRENT_SOURCE_DIR}/harfbuzz/src/hb-buffer-deserialize-json.rl
  BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-buffer-deserialize-json.hh
  DEPENDS kscheduler-harfbuzz-dummy
)
add_custom_target(
  kscheduler-harfbuzz-hb-buffer-deserialize-text.hh
  COMMAND ragel -e -F1 -o ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-buffer-deserialize-text.hh ${CMAKE_CURRENT_SOURCE_DIR}/harfbuzz/src/hb-buffer-deserialize-text.rl
  BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-buffer-deserialize-text.hh
  DEPENDS kscheduler-harfbuzz-hb-buffer-deserialize-json.hh
)
add_custom_target(
  kscheduler-harfbuzz-hb-ot-shape-complex-indic-machine.hh
  COMMAND ragel -e -F1 -o ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-ot-shape-complex-indic-machine.hh ${CMAKE_CURRENT_SOURCE_DIR}/harfbuzz/src/hb-ot-shape-complex-indic-machine.rl
  BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-ot-shape-complex-indic-machine.hh
  DEPENDS kscheduler-harfbuzz-hb-buffer-deserialize-text.hh
)
add_custom_target(
  kscheduler-harfbuzz-hb-ot-shape-complex-myanmar-machine.hh
  COMMAND ragel -e -F1 -o ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-ot-shape-complex-myanmar-machine.hh ${CMAKE_CURRENT_SOURCE_DIR}/harfbuzz/src/hb-ot-shape-complex-myanmar-machine.rl
  BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-ot-shape-complex-myanmar-machine.hh
  DEPENDS kscheduler-harfbuzz-hb-ot-shape-complex-indic-machine.hh
)
add_custom_target(
  kscheduler-harfbuzz-hb-ot-shape-complex-use-machine.hh
  COMMAND ragel -e -F1 -o ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-ot-shape-complex-use-machine.hh ${CMAKE_CURRENT_SOURCE_DIR}/harfbuzz/src/hb-ot-shape-complex-use-machine.rl
  BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-ot-shape-complex-use-machine.hh
  DEPENDS kscheduler-harfbuzz-hb-ot-shape-complex-myanmar-machine.hh
)


add_executable(
  kscheduler-harfbuzz
  StandaloneFuzzTargetMain.cpp
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-blob.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-buffer-serialize.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-buffer.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-common.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-face.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-font.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-tag.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-shape.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-shape-plan.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-shaper.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-unicode.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-warning.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-font.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-layout.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-map.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-arabic.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-default.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-hangul.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-hebrew.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-indic.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-indic-table.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-myanmar.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-thai.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-tibetan.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-use.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-complex-use-table.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-normalize.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ot-shape-fallback.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-fallback-shape.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ucdn.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-ucdn/ucdn.c
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/src/hb-icu.cc
  ${FUZZUF_HARFBUZZ_SOURCE_DIR}/test/fuzzing/hb-fuzzer.cc
)

target_include_directories(
  kscheduler-harfbuzz
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/harfbuzz/src
  ${CMAKE_CURRENT_SOURCE_DIR}/harfbuzz/src/hb-ucdn
  ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/
  ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src
  ${CMAKE_CURRENT_BINARY_DIR}/kscheduler-harfbuzz-dummy-prefix/src/kscheduler-harfbuzz-dummy-build/src/hb-ucdn
  ${ICU_INCLUDE_DIRS}
)

target_link_directories(
  kscheduler-harfbuzz
  PUBLIC
  ${ICU_LIBRARY_DIRS}
)

target_link_libraries(
  kscheduler-harfbuzz
  ${ICU_LIBRARIES}
)

add_dependencies(
  kscheduler-harfbuzz
  kscheduler-harfbuzz-dummy
  kscheduler-harfbuzz-hb-buffer-deserialize-json.hh
  kscheduler-harfbuzz-hb-buffer-deserialize-text.hh
  kscheduler-harfbuzz-hb-ot-shape-complex-indic-machine.hh
  kscheduler-harfbuzz-hb-ot-shape-complex-myanmar-machine.hh
  kscheduler-harfbuzz-hb-ot-shape-complex-use-machine.hh
)

target_compile_definitions(
  kscheduler-harfbuzz
  PUBLIC HAVE_CONFIG_H
)

set_target_properties(
  kscheduler-harfbuzz
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)


get_katz_centricity( kscheduler-harfbuzz )

endif()

