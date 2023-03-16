find_program(MAKE_EXE NAMES gmake nmake make)
set( QEMU_VERSION )
set( ECLIPSER_QEMU_VERSION "2.10.0" )
ExternalProject_Add(
  qemu-trace-coverage-x86_64
  URL https://download.qemu.org/qemu-${ECLIPSER_QEMU_VERSION}.tar.bz2
  URL_HASH MD5=ca73441de73a9b52c6c49c97190d2185
  PATCH_COMMAND
    "${CMAKE_CURRENT_SOURCE_DIR}/patch.sh"
    "<SOURCE_DIR>"
    "${CMAKE_CURRENT_SOURCE_DIR}/../"
  CONFIGURE_COMMAND
    "<SOURCE_DIR>/configure"
    "--prefix=<INSTALL_DIR>"
    "--disable-system"
    "--enable-linux-user"
    "--disable-gtk"
    "--disable-sdl"
    "--disable-vnc"
    "--python=python2.7"
    "--target-list=x86_64-linux-user"
  BUILD_COMMAND "${MAKE_EXE}"
  INSTALL_COMMAND "${MAKE_EXE}" "install"
  LOG_PATCH TRUE
  LOG_CONFIGURE TRUE
  LOG_BUILD TRUE
  LOG_INSTALL TRUE
  LOG_OUTPUT_ON_FAILURE TRUE
)

install( PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/qemu-trace-coverage-x86_64-prefix/bin/qemu-x86_64 DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME qemu-trace-coverage-x64 )
