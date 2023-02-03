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
if( "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64" )
  if ( DEFINED AFL_ROOT )
    find_program(
      FRIDA_TRACE_SO
      afl-frida-trace.so
      HINTS ${AFL_ROOT}/
    )
  else()
    message( STATUS "afl-frida-trace.so location is not specified." )
  endif()
  if ( DEFINED FRIDA_TRACE_SO )
    file(
      COPY ${FRIDA_TRACE_SO}
      DESTINATION ${CMAKE_BINARY_DIR}
    )
  endif()
endif()
