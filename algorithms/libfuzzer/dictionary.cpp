/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#include "fuzzuf/algorithms/libfuzzer/dictionary.hpp"
#include "fuzzuf/utils/afl_dict_parser.hpp"

namespace fuzzuf::algorithm::libfuzzer::dictionary {

/**
 * @fn
 * filenameで指定されたAFL辞書をdestにロードする
 * destに最初から要素がある場合、ロードした内容は既にある要素の後ろにinsertされる
 * @brief filenameで指定されたAFL辞書をdestにロードする
 * @param filename ファイル名
 * @param dest ロードした内容の出力先
 * @param eout
 * ファイルのパースに失敗した場合にエラーメッセージが文字列で渡ってくるコールバック
 */
void Load(const std::string &filename_, StaticDictionary &dest, bool strict,
          const std::function<void(std::string &&)> &eout) {
  utils::dictionary::LoadAFLDictionary(filename_, dest, strict, eout);
}

/**
 * @fn
 * filenameで指定されたAFL辞書をdestにロードする
 * destに最初から要素がある場合、ロードした内容は既にある要素の後ろにinsertされる
 * @brief filenameで指定されたAFL辞書をdestにロードする
 * @param filename ファイル名
 * @param dest ロードした内容の出力先
 * @param eout
 * ファイルのパースに失敗した場合にエラーメッセージが文字列で渡ってくるコールバック
 */
void Load(const std::string &filename_, DynamicDictionary &dest, bool strict,
          const std::function<void(std::string &&)> &eout) {
  utils::dictionary::LoadAFLDictionary(filename_, dest, strict, eout);
}

/**
 * @fn
 * pathsで指定されたAFL辞書を順番にdestにロードする
 * destに最初から要素がある場合、ロードした内容は既にある要素の後ろにinsertされる
 * @param paths AFL辞書へのパスを要素とするrange
 * @param dest ロードした内容の出力先
 * @param eout
 * ファイルのパースに失敗した場合にエラーメッセージが文字列で渡ってくるコールバック
 */
void Load(const std::vector<fs::path> &paths, StaticDictionary &dest,
          bool strict, const std::function<void(std::string &&)> &eout) {
  for (const auto &path : paths) {
    Load(path.string(), dest, strict, eout);
  }
}

/**
 * @fn
 * pathsで指定されたAFL辞書を順番にdestにロードする
 * destに最初から要素がある場合、ロードした内容は既にある要素の後ろにinsertされる
 * @param paths AFL辞書へのパスを要素とするrange
 * @param dest ロードした内容の出力先
 * @param eout
 * ファイルのパースに失敗した場合にエラーメッセージが文字列で渡ってくるコールバック
 */
void Load(const std::vector<fs::path> &paths, DynamicDictionary &dest,
          bool strict, const std::function<void(std::string &&)> &eout) {
  for (const auto &path : paths) {
    Load(path.string(), dest, strict, eout);
  }
}

} // namespace fuzzuf::algorithm::libfuzzer::dictionary
