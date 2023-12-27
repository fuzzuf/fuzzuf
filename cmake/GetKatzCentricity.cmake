add_custom_target(networkit
  COMMAND pip3 install --target=${CMAKE_BINARY_DIR}/nk networkx networkit numpy==1.23 scipy ipdb
  COMMENT "Installing networkit..."
  BYPRODUCTS ${CMAKE_BINARY_DIR}/nk/libnetworkit.so
  VERBATIM)

function(get_katz_centricity TARGET)

  set(current-input-path ${CMAKE_CURRENT_BINARY_DIR}/${TARGET})
  set(current-output-path ${CMAKE_CURRENT_BINARY_DIR}/katz_cent)

  add_custom_command(
    OUTPUT ${current-output-path}
    COMMAND ${CMAKE_SOURCE_DIR}/tools/kscheduler/gen_graph.sh ${CMAKE_BINARY_DIR}/nk ${current-input-path}
    DEPENDS ${current-input-path} networkit
    VERBATIM)

  set_source_files_properties(${current-output-path} PROPERTIES GENERATED TRUE)
  target_sources(${TARGET} PRIVATE ${current-output-path})
endfunction(get_katz_centricity)

