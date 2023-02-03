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
/**
 * @file which.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_WHICH_HPP
#define FUZZUF_INCLUDE_UTILS_WHICH_HPP
#include "fuzzuf/utils/filesystem.hpp"
namespace fuzzuf::utils {

// PATHに基づいて実行可能バイナリの場所を特定する
// nameが絶対パスの場合、nameがそのまま返る
//   例: /hoge/fuga
// nameが親ディレクトリの名前を1つ以上持つ場合、nameがそのまま返る
//   例: ../fuga
// 環境変数PATHの要素/nameが存在する場合、環境変数PATHの要素/nameが返る
// 候補が複数ある場合PATHに先に書かれた要素が優先される
//   例: bash
// それ以外の場合、nameがそのまま返る
auto which(const fs::path &name) -> fs::path;

}  // namespace fuzzuf::utils
#endif
