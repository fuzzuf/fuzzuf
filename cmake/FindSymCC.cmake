if(NOT SYMCC_ROOT)
  find_program( SYMCC_CC symcc )
  find_program( SYMCC_CXX sym++ )
else()
  find_program( SYMCC_CC symcc NO_DEFAULT_PATH PATHS ${SYMCC_ROOT}/ ${SYMCC_ROOT}/bin/ )
  find_program( SYMCC_CXX sym++ NO_DEFAULT_PATH PATHS ${SYMCC_ROOT}/ ${SYMCC_ROOT}/bin/ )
endif()
if( NOT SYMCC_LIBCXX_ROOT )
  find_path(SYMCC_LIBCXX_PREFIX c++/v1/algorithm
    PATHS
    /usr/lib/llvm-14/include
    /usr/lib/llvm-13/include
    /usr/lib/llvm-12/include
    /usr/lib/llvm-11/include
    /usr/lib/llvm-10/include
    /usr/lib/llvm-9/include
    ${CMAKE_SYSTEM_PREFIX_PATH}
  )
else()
  find_path(SYMCC_LIBCXX_PREFIX c++/v1/algorithm
    PATHS
    ${SYMCC_LIBCXX_ROOT}
  )
endif()
set( SYMCC_CC_PROXY ${CMAKE_BINARY_DIR}/symcc_proxy )
set( SYMCC_CXX_PROXY ${CMAKE_BINARY_DIR}/sym++_proxy )

FIND_PACKAGE_HANDLE_STANDARD_ARGS(
  SYMCC
  REQUIRED_VARS SYMCC_CC SYMCC_CXX SYMCC_LIBCXX_PREFIX SYMCC_CC_PROXY SYMCC_CXX_PROXY
)

configure_file(
  "${CMAKE_SOURCE_DIR}/check/symcc_proxy.in"
  "${CMAKE_BINARY_DIR}/symcc_proxy"
)

configure_file(
  "${CMAKE_SOURCE_DIR}/check/sym++_proxy.in"
  "${CMAKE_BINARY_DIR}/sym++_proxy"
)

