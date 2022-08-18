#
# fuzzuf-cc
# Copyright (C) 2022 Ricerca Security
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
if( NOT LIBBFD_ROOT )
	find_path (LIBBFD_INCLUDE_DIRS NAMES bfd.h PATHS /usr/include /usr/local/include )
  find_library (LIBBFD_LIBRARY NAMES bfd )
else()
  find_path (LIBBFD_INCLUDE_DIRS NAMES bfd.h PATHS ${LIBBFD_ROOT}/include )
  find_library (LIBBFD_LIBRARY NAMES bfd PATHS ${LIBBFD_ROOT}/lib ${LIBBFD_ROOT}/lib64 ${LIBBFD_ROOT} NO_DEFAULT_PATH )
endif()
include (FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  LIBBFD DEFAULT_MSG
  LIBBFD_INCLUDE_DIRS LIBBFD_LIBRARY
)
set(LIBBFD_LIBRARIES "${LIBBFD_LIBRARY}")
mark_as_advanced(LIBBFD_INCLUDE_DIRS LIBBFD_LIBRARIES LIBBFD_LIBRARY)
