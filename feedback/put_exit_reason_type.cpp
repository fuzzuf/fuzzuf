/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
#include "fuzzuf/feedback/put_exit_reason_type.hpp"

#include <ostream>

namespace fuzzuf::feedback {

// Pass just raw integer value
std::ostream& boost_test_print_type(std::ostream& ostr,
                                    PUTExitReasonType const& val) {
  ostr << static_cast<int>(val);
  return ostr;
}

bool toString(std::string& dest, PUTExitReasonType value) {
  if (value == PUTExitReasonType::FAULT_NONE)
    dest += "FAULT_NONE";
  else if (value == PUTExitReasonType::FAULT_TMOUT)
    dest += "FAULT_TMOUT";
  else if (value == PUTExitReasonType::FAULT_CRASH)
    dest += "FAULT_CRASH";
  else if (value == PUTExitReasonType::FAULT_ERROR)
    dest += "FAULT_ERROR";
  else if (value == PUTExitReasonType::FAULT_NOINST)
    dest += "FAULT_NOINST";
  else if (value == PUTExitReasonType::FAULT_NOBITS)
    dest += "FAULT_NOBITS";
  else
    return false;
  return true;
}

}  // namespace fuzzuf::feedback
