FOREACH( alg ${ALGORITHMS} )
  if( EXISTS ${CMAKE_SOURCE_DIR}/test/algorithms/${alg} AND IS_DIRECTORY ${CMAKE_SOURCE_DIR}/test/algorithms/${alg} )
  subdirs(
    ${alg}
  )  
  endif()
ENDFOREACH()

