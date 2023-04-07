### アルファベット順に並べてください
subdirs(
  algorithms
  cli
  common
  exec_input
  executor
  hierarflow
  put_binaries
  util
  put
)
algorithm_enabled( python_wrapper_enabled "${ALGORITHMS}" "python" )
if( python_wrapper_enabled )
subdirs(
  fuzzer
  instrument
  profile
  python
)
endif()
afl_common_is_required( enable_afl_common "${ALGORITHMS}" )
if( enable_afl_common )
subdirs(
  mutator
)
endif()
