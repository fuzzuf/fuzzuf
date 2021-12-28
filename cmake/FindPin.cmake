message( ${CMAKE_SYSTEM_PROCESSOR} )

set( PIN_ARCH "" )
if( "${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "x86_64" )
  set( PIN_HOST_ARCHITECTURE "HOST_IA32E" )
elseif( "${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "x86" )
  set( PIN_HOST_ARCHITECTURE "TARGET_IA32" )
endif()

if( "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64" )
  set( PIN_ARCH "intel64" )
  set( PIN_TARGET_ARCHITECTURE "TARGET_IA32E" )
elseif( "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86" )
  set( PIN_ARCH "ia32" )
  set( PIN_TARGET_ARCHITECTURE "TARGET_IA32" )
endif()

if(WIN32)
  set( PIN_PLATFORM "TARGET_WINDOWS" )
elseif(APPLE)
  set( PIN_PLATFORM "TARGET_MAC" )
elseif(UNIX)
  if( "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" )
    set( PIN_PLATFORM "TARGET_LINUX" )
  endif()
endif()

if( "${PIN_PLATFORM}" STREQUAL "" )
  message( "Intel Pin is not supported on the platform : ${CMAKE_SYSTEM_NAME}" )
endif()

if( "${PIN_ARCH}" STREQUAL "" )
  message( "Intel Pin is not available on the architecture : ${CMAKE_SYSTEM_PROCESSOR}" )
elseif( "${PIN_ROOT}" STREQUAL "" )
  message( "Intel Pin location (PIN_ROOT) is not specified." )
else()
  find_program( PIN_EXECUTABLE pin HINTS ${PIN_ROOT}/ )
  find_path( PIN_INCLUDE_DIR pin.H NO_DEFAULT_PATH PATHS ${PIN_ROOT}/source/include/pin/)
  find_path( PIN_GEN_INCLUDE_DIR pinsync.hpp NO_DEFAULT_PATH PATHS ${PIN_ROOT}/source/include/pin/gen/)
  find_path( PIN_XED_INCLUDE_DIR xed-interface.h NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/xed-${PIN_ARCH}/include/xed/)
  find_path( PIN_CRT_INCLUDE_DIR types_marker.h NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/crt/include/)
  find_path( PIN_CRT_UAPI_INCLUDE_DIR linux/compiler.h NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/crt/include/kernel/uapi )
  find_path( PIN_CRT_ARCH_INCLUDE_DIR machine/endian.h NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/crt/include/arch-${CMAKE_SYSTEM_PROCESSOR}/ )
  find_path( PIN_CRT_ASM_INCLUDE_DIR asm/types.h NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/crt/include/kernel/uapi/asm-x86 )
  find_path( PIN_CRT_LINUX_INCLUDE_DIR stddef.h NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/crt/include/kernel/uapi/linux/ )
  find_path( PIN_LIBUNWIND_INCLUDE_DIR unwind.h NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/libunwind/include )
  find_path( PIN_LIBSTDCXX_INCLUDE_DIR cerrno NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/libstdc++/include )
  find_path( PIN_COMPONENTS_INCLUDE_DIR atomic.hpp NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/components/include )
  find_path( PIN_STLPORT_INCLUDE_DIR stddef.h NO_DEFAULT_PATH PATHS ${PIN_ROOT}/extras/stlport/include )
  find_path( PIN_CRT_LIBRARY_DIR ${CMAKE_SHARED_LIBRARY_PREFIX}c-dynamic${CMAKE_SHARED_LIBRARY_SUFFIX} NO_DEFAULT_PATH PATHS ${PIN_ROOT}/${PIN_ARCH}/runtime/pincrt )
  find_path( PIN_LIBRARY_DIR ${CMAKE_STATIC_LIBRARY_PREFIX}pin${CMAKE_STATIC_LIBRARY_SUFFIX} NO_DEFAULT_PATH PATHS ${PIN_ROOT}/intel64/lib )
  find_path( PIN_LIBEXT_DIR ${CMAKE_SHARED_LIBRARY_PREFIX}pin3dwarf${CMAKE_SHARED_LIBRARY_SUFFIX} NO_DEFAULT_PATH PATHS ${PIN_ROOT}/intel64/lib-ext )
  find_path( PIN_LIBXED_DIR ${CMAKE_SHARED_LIBRARY_PREFIX}xed${CMAKE_SHARED_LIBRARY_SUFFIX} ${PIN_ROOT}/extras/xed-${PIN_ARCH}/lib )
  find_path( PIN_RUNTIME_DIR crtbegin.o ${PIN_ROOT}/intel64/runtime/pincrt/ )
  find_library( PIN_LIBRARY pin HINTS ${PIN_LIBRARY_DIR} )
  find_library( PIN_XED_LIBRARY xed HINTS ${PIN_LIBXED_DIR} )
  find_library( PIN_PIN3DWARF_LIBRARY pin3dwarf HINTS ${PIN_LIBEXT_DIR} )
  find_library( PIN_C_DYNAMIC_LIBRARY c-dynamic HINTS ${PIN_CRT_LIBRARY_DIR} )
  find_library( PIN_M_DYNAMIC_LIBRARY m-dynamic HINTS ${PIN_CRT_LIBRARY_DIR} )
  find_library( PIN_DL_DYNAMIC_LIBRARY dl-dynamic HINTS ${PIN_CRT_LIBRARY_DIR} )
  find_library( PIN_UNWIND_DYNAMIC_LIBRARY unwind-dynamic HINTS ${PIN_CRT_LIBRARY_DIR} )
  find_library( PIN_STLPORT_DYNAMIC_LIBRARY stlport-dynamic HINTS ${PIN_CRT_LIBRARY_DIR} )
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  PIN
  REQUIRED_VARS
    PIN_LIBRARY
    PIN_XED_LIBRARY
    PIN_PIN3DWARF_LIBRARY
    PIN_C_DYNAMIC_LIBRARY
    PIN_M_DYNAMIC_LIBRARY
    PIN_DL_DYNAMIC_LIBRARY
    PIN_UNWIND_DYNAMIC_LIBRARY
    PIN_STLPORT_DYNAMIC_LIBRARY
    PIN_LIBRARY_DIR
    PIN_LIBEXT_DIR
    PIN_LIBXED_DIR
    PIN_CRT_LIBRARY_DIR
    PIN_RUNTIME_DIR
    PIN_INCLUDE_DIR
    PIN_GEN_INCLUDE_DIR
    PIN_XED_INCLUDE_DIR
    PIN_CRT_INCLUDE_DIR
    PIN_CRT_UAPI_INCLUDE_DIR
    PIN_CRT_ARCH_INCLUDE_DIR
    PIN_CRT_ASM_INCLUDE_DIR
    PIN_CRT_LINUX_INCLUDE_DIR
    PIN_LIBUNWIND_INCLUDE_DIR
    PIN_LIBSTDCXX_INCLUDE_DIR
    PIN_COMPONENTS_INCLUDE_DIR
    PIN_STLPORT_INCLUDE_DIR
    PIN_TARGET_ARCHITECTURE
)
set(
  PIN_LIBRARIES
    ${PIN_LIBRARY}
    ${PIN_XED_LIBRARY}
    ${PIN_DL_DYNAMIC_LIBRARY}
    ${PIN_PIN3DWARF_LIBRARY}
    ${PIN_C_DYNAMIC_LIBRARY}
    ${PIN_STLPORT_DYNAMIC_LIBRARY}
    ${PIN_M_DYNAMIC_LIBRARY}
    ${PIN_UNWIND_DYNAMIC_LIBRARY}
)
set(
  PIN_INCLUDE_DIRS
    ${PIN_INCLUDE_DIR}
    ${PIN_GEN_INCLUDE_DIR}
    ${PIN_XED_INCLUDE_DIR} 
    ${PIN_COMPONENTS_INCLUDE_DIR}
)
set(
  PIN_LIBRARY_DIRS
    ${PIN_CRT_LIBRARY_DIR}
    ${PIN_LIBRARY_DIR}
    ${PIN_LIBEXT_DIR}
    ${PIN_LIBXED_DIR}
    ${PIN_RUNTIME_DIR}
)
set(
  PIN_DEFINITIONS
    __PIN__=1
    PIN_CRT=1
    ${PIN_TARGET_ARCHITECTURE}
    ${PIN_HOST_ARCHITECTURE}
    ${PIN_PLATFORM}
)
set(
  PIN_COMPILE_FLAGS " \
    -fno-stack-protector \
    -fno-exceptions \
    -funwind-tables \
    -fasynchronous-unwind-tables \
    -fno-rtti \
    -fomit-frame-pointer \
    -fno-strict-aliasing \
    -fPIC \
    -fabi-version=2 \
    -isystem ${PIN_STLPORT_INCLUDE_DIR} \
    -isystem ${PIN_LIBSTDCXX_INCLUDE_DIR} \
    -isystem ${PIN_CRT_INCLUDE_DIR} \
    -isystem ${PIN_CRT_ARCH_INCLUDE_DIR} \
    -isystem ${PIN_CRT_UAPI_INCLUDE_DIR} \
    -isystem ${PIN_CRT_ASM_INCLUDE_DIR} \
  "
)
set(
  PIN_LINK_FLAGS " \
    -shared \
    -Wl,--hash-style=sysv \
    ${PIN_RUNTIME_DIR}/crtbeginS.o \
    -Wl,-Bsymbolic \
    -Wl,--version-script=${PIN_INCLUDE_DIR}/pintool.ver \
    -fabi-version=2 \
    ${PIN_RUNTIME_DIR}/crtendS.o \
    -nostdlib \
  "
)
message( "Intel Pin libraries: ${PIN_LIBRARIES}" )
message( "Intel Pin include dirs: ${PIN_INCLUDE_DIRS}" )
message( "Intel Pin library dirs: ${PIN_LIBRARY_DIRS}" )
message( "Intel Pin definitions: ${PIN_DEFINITIONS}" )
message( "Intel Pin compile flags: ${PIN_COMPILE_FLAGS}" )
message( "Intel Pin link flags: ${PIN_LINK_FLAGS}" )
mark_as_advanced(
  PIN_LIBRARIES
  PIN_INCLUDE_DIRS
  PIN_LIBRARY_DIRS
  PIN_DEFINITIONS
  PIN_COMPILE_FLAGS
  PIN_LINK_FLAGS
)

