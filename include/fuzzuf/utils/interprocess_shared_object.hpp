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
#ifndef FUZZUF_INCLUDE_UTILS_INTERPROCESS_SHARED_OBJECT_HPP
#define FUZZUF_INCLUDE_UTILS_INTERPROCESS_SHARED_OBJECT_HPP
#include "fuzzuf/utils/shared_range.hpp"
#include <boost/range/iterator_range.hpp>
#include <cstdint>
#include <memory>
#include <new>
#include <sys/mman.h>
#include <type_traits>

namespace fuzzuf::utils::interprocess {

/*
 * T型の子プロセスと共有されるインスタンスを作る
 * TはTrivially Copyableの要件を満たさなければならない
 * インスタンスは引数で渡した値で初期化される
 *
 * 共有はMAP_SHARED|MAP_ANNONYMOUSなメモリをmmapする事で
 * 実現されている
 * 故にページサイズを下回るサイズ型であっても少なく
 * とも1ページは確保される事になる
 * また、この関数の呼び出しは確実にシステムコールを
 * 生じさせる
 * このため、小さい値を沢山共有する必要がある場合は
 * それらを構造体にまとめて大きな塊にしてから
 * create_shared_objectするのが望ましい
 *
 * 返り値はdeleterでmunmapするshared_ptr< T >
 *
 * mmapが失敗した場合(ex. 空きメモリがない)
 * 例外std::bad_allocが飛ぶ
 */
template <typename T>
auto create_shared_object(const T &v)
    -> std::enable_if_t<std::is_trivially_copyable_v<T>, std::shared_ptr<T>> {
  auto addr = mmap(nullptr, sizeof(T), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (addr == reinterpret_cast<void *>(std::intptr_t(-1)))
    throw std::bad_alloc();
  return std::shared_ptr<T>(new (addr) T(v),
                            [addr](auto) { munmap(addr, sizeof(T)); });
}

} // namespace fuzzuf::utils::interprocess
#endif
