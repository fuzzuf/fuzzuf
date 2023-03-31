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
#pragma once

#include <ostream>
#include <string>

namespace fuzzuf::feedback {

// PUTの実行が終了した理由の種別(AFL互換)
enum class PUTExitReasonType {
  FAULT_NONE,    // 正常終了
  FAULT_TMOUT,   // 実行時間の制限超過
  FAULT_CRASH,   // SEGVなどによるcrash
  FAULT_ERROR,   // 実行がそもそもできなかったなど
  FAULT_NOINST,  // おそらくinstrumentが見つからなかった場合のエラーだが今使われていない
  FAULT_NOBITS   // 用途不明
};

// we need to give how to print these enum values, for tests using boost
std::ostream& boost_test_print_type(std::ostream& ostr,
                                    PUTExitReasonType const& val);

bool toString(std::string&, PUTExitReasonType);

}  // namespace fuzzuf::feedback
