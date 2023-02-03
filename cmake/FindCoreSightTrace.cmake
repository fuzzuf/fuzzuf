#
# fuzzuf
# Copyright (C) 2021-2023 Ricerca Security
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.
#
# FIXME: This cmake file does not consider cross-compile
if( "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" )
  if( DEFINED AFL_ROOT )
    find_program(
      CS_PROXY_EXECUTABLE
      afl-cs-proxy
      HINTS ${AFL_ROOT}/
    )
  elseif( DEFINED CORESIGHT_TRACE_ROOT )
    find_program(
      CS_PROXY_EXECUTABLE
      cs-proxy
      HINTS ${CORESIGHT_TRACE_ROOT}/
    )
  else()
    message( STATUS "coresight-trace location is not specified." )
  endif()
endif()

find_package_handle_standard_args(
  CORESIGHT_TRACE
  REQUIRED_VARS CS_PROXY_EXECUTABLE
)
