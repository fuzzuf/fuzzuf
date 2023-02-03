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
 * @file sha1.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/sha1.hpp"

#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>

#include <boost/spirit/include/karma.hpp>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

namespace fuzzuf::utils::detail {
#if CRYPTOPP_MAJOR < 6
static auto ToHex(const std::vector<byte> &v) -> std::string {
#else
static auto ToHex(const std::vector<CryptoPP::byte> &v) -> std::string {
#endif
  std::string serialized;
  namespace karma = boost::spirit::karma;
  karma::generate(std::back_inserter(serialized),
                  *karma::right_align(2, '0')[karma::hex], v);
  return serialized;
}
auto ToSerializedSha1Contiguous(const std::vector<std::uint8_t> &range)
    -> std::string {
  CryptoPP::SHA1 sha1;
  sha1.Update(range.data(), range.size());
#if CRYPTOPP_MAJOR < 6
  std::vector<byte> digest(sha1.DigestSize());
#else
  std::vector<CryptoPP::byte> digest(sha1.DigestSize());
#endif
  sha1.Final(digest.data());
  return ToHex(digest);
}
}  // namespace fuzzuf::utils::detail
