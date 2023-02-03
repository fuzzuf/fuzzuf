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
 * @file GetHash.cpp
 * @brief Calculate SHA1 hash
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/get_hash.hpp"

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

namespace fuzzuf::utils {
std::string GetSHA1HashFromFile(std::string path, u32 len) {
  int fd = fuzzuf::utils::OpenFile(path, O_RDONLY);
  u8 *buf = new u8[len];
  fuzzuf::utils::ReadFile(fd, buf, len);
  fuzzuf::utils::CloseFile(fd);

  CryptoPP::SHA1 sha1;
  std::string hash = "";

  CryptoPP::StringSource(
      buf, len, true,
      new CryptoPP::HashFilter(
          sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
  delete[] buf;
  return hash;
}
}  // namespace fuzzuf::utils
