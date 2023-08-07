
foreach( alg ${ALGORITHMS} )
  if( EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${alg} )
    if( IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${alg} )
    add_subdirectory(
      ${alg}
    ) 
    endif()
  endif()
endforeach()

