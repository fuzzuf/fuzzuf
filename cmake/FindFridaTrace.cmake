if ( EXISTS "${CMAKE_BINARY_DIR}/afl-frida-trace.so" )
  message("[*] afl-frida-trace.so already exists.")
elseif ( DEFINED ENABLE_FRIDA_TRACE )
  message("[+] Building afl-frida-trace.so from AFLplusplus submodule...")
  execute_process(
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/build_frida_trace.sh
      ${CMAKE_SOURCE_DIR}/AFLplusplus
      ${CMAKE_BINARY_DIR}
    COMMENT "Setting up frida mode..."
    DEPENDS ${CMAKE_SOURCE_DIR}/scripts/build_frida_trace.sh
    VERBATIM
  )
endif()
