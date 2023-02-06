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
#ifndef __COMMON_HPP__
#define __COMMON_HPP__

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "fuzzuf/utils/status.hpp"

#define XXH_INLINE_ALL
#include "third_party/xxHash/xxhash.h"
#undef XXH_INLINE_ALL

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#if defined(__x86_64__) || defined(__aarch64__)
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

namespace fuzzuf::executor {
using output_t = std::vector<std::uint8_t>;
}

#define SWAP16(_x)                    \
  ({                                  \
    u16 _ret = (_x);                  \
    (u16)((_ret << 8) | (_ret >> 8)); \
  })

#define SWAP32(_x)                                                   \
  ({                                                                 \
    u32 _ret = (_x);                                                 \
    (u32)((_ret << 24) | (_ret >> 24) | ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00));                               \
  })

#define likely(_x) __builtin_expect(!!(_x), 1)
#define unlikely(_x) __builtin_expect(!!(_x), 0)

#define MEM_BARRIER() __asm__ volatile("" ::: "memory")

// Define DEBUG_ASSERT, which is enabled only when the build mode is "Debug".
// NOTE: We know assert can be enabled and disabled already with NDEBUG.
// But, NDEBUG can be set/unset by CMake or other build systems with stealth.
// Due to this fact, writing "assert()" everywhere may get on our nerves
// becuase we would be worried if assert might be enabled even in Release mode.
// It would be better if we could have another assert function,
// which guarantees that it's never called in Release mode build.
#ifdef DEFINE_DEBUG_ASSERT
#define DEBUG_ASSERT(...) assert(__VA_ARGS__)
#else
// To avoid Wempty-body in "if (...) DEBUG_ASSERT(...);",
// we need some value.
#define DEBUG_ASSERT(...) \
  do {                    \
  } while (0)
#endif

#define UNUSED(UNUSED_VAR) (void)(UNUSED_VAR)

namespace fuzzuf::utils {

// Instead of T*, we should use T& and this in usual cases because T* is
// ambiguous in the point that we can't see whether the pointer refers to array
// or an element also raw pointers are relatively dangerous
template <class T>
using NullableRef = std::optional<std::reference_wrapper<T>>;

class InvalidOption : public std::invalid_argument {
 public:
  InvalidOption(const std::string &what_arg)
      : std::invalid_argument(what_arg) {}
};

class FileError : public std::invalid_argument {
 public:
  FileError(const std::string &what_arg) : std::invalid_argument(what_arg) {}
};

/*
namespace {
    template<typename T>
    struct func_trait;

    template<typename R, typename... P>
    struct func_trait<R(P...)> {
        using return_type_t = R;
        using args_type_t = P;
    };
};

template<class T>
using GetReturnType = typename func_trait<T>::return_type_t;

template<class T>
using GetFuncArgsType = typename func_trait<T>::args_type_t;
*/

int ExecuteCommand(std::vector<std::string> &args);

void CreateDir(std::string path);

int OpenFile(std::string path, int flag);
int OpenFile(std::string path, int flag, mode_t mode);

ssize_t GetFileSize(int fd);

ssize_t read_n(int fd, void *buf, size_t n, bool original_behaviour);
ssize_t write_n(int fd, const void *buf, size_t n);
ssize_t ReadFile(int fd, void *buf, u32 len, bool original_behaviour = true);
u32 ReadFileTimed(int fd, void *buf, u32 len, u32 timeout_ms);
ssize_t ReadFileAll(int fd, fuzzuf::executor::output_t &buf);

ssize_t WriteFile(int fd, const void *buf, u32 len);
void WriteFileStr(int fd, std::string str);

int FSync(int fd);

off_t SeekFile(int fd, off_t offset, int whence);

int TruncateFile(int fd, off_t length);

void CopyFile(std::string from, std::string to);
void CloseFile(int fd);

void DeleteFileOrDirectory(std::string path);

int ScanDirAlpha(std::string dir, struct dirent ***namelist);

// Constant values used by `BindCpu()` to indicate CPU binding policy.
constexpr int CPUID_DO_NOT_BIND = -2;
constexpr int CPUID_BIND_WHICHEVER = -1;

bool IsValidCpuId(int cpuid);
int GetCpuCore();
std::set<int> GetFreeCpu(int);
int BindCpu(int, int);

u64 NextP2(u64);

pid_t Fork();

u64 GetCurTimeUs();
u64 GetCurTimeMs();

u32 MurmurHash32(const void *key, u32 len, u32 seed);
inline u32 Hash32(const void *key, u32 len, [[maybe_unused]] u32 seed) {
  return static_cast<u32>(XXH3_64bits(key, len));
}

u32 CountBits(const u8 *mem, u32 len);
u32 CountBytes(const u8 *mem, u32 len);
u32 CountNon255Bytes(const u8 *mem, u32 len);

void MinimizeBits(u8 *dst, const u8 *src, u32 len);

std::tuple<s32, s32> LocateDiffs(const u8 *ptr1, const u8 *ptr2, u32 len);

std::string StrPrintf(const char *format, ...);

u64 GlobalCounter();

class set_segv_handler {
 public:
  set_segv_handler(const set_segv_handler &) = delete;
  set_segv_handler(set_segv_handler &&) = delete;
  set_segv_handler &operator-(const set_segv_handler &) = delete;
  set_segv_handler &operator=(set_segv_handler &&) = delete;
  static const set_segv_handler &get();

 private:
  set_segv_handler();
};
/**
 * この関数の呼び出し以降、log()に渡されたログがurlで指定されたfluentdに送られる
 * ローカルホストの24224番ポートで動くfluentdに接続するには"fluent://localhost:24224"を設定する
 * 接続先のポートが24224番(デフォルト)の場合はポート番号は省略できる
 * init_loggerを再度呼び出す事でログの送信先を変更できるが、変更した時点で既に送信準備に入っていたログがinit_loggerの呼び出し後に古い送信先に送られる可能性がある
 * init_logger時点では実際の接続は行われない為、指定された送信先に実際にログを送れるかはチェックされない
 * ログを受け取るfluentdはurlに指定したアドレスでforward
 *inputを待ち受けている必要がある
 * @brief ログの送信先のfluentdのURLを設定する
 * @param url 接続先のfluentdのURL
 **/
void init_logger(const std::string &url);
/**
 * log()に渡されたログがfluentdに送られる状態になっているかを確認する
 * この関数は送信先が設定されていることだけをチェックする為、実際にfluentdがログを受け取れる状態になっているかはこの関数の結果に影響しない
 * @brief ログの送信先が設定されているかを確認する
 * @return 送信先のfluentdが設定されていればtrue、そうでなければfalseが返る
 **/
bool has_logger();
/**
 * init_loggerで設定された送信先に文字列のログを送る
 * 文字列はそれがJSONとして解釈可能な場合JSONとしてパースしてfluentdに送られる
 * JSONとして解釈できない文字列の場合、その文字列だけを含むJSONとしてfluentdに送られる
 * ログのタグはfuzzuf.<親プロセスのPID>.<自身のPID>.<tagで指定した値>になる
 * この関数はログの送信を送信キューに積んで送信完了を待たずに返る
 * @brief ログを送信する
 * @param tag このログのタグを指定する
 * @param message ログ
 * @param cb ログの送信が完了または失敗した際に呼ばれるコールバック
 **/
void log(std::string &&tag, std::string &&message,
         std::function<void(status_t)> &&cb);
/**
 * init_loggerで設定された送信先に文字列のログを送る
 * 文字列はそれがJSONとして解釈可能な場合JSONとしてパースしてfluentdに送られる
 * JSONとして解釈できない文字列の場合、その文字列だけを含むJSONとしてfluentdに送られる
 * ログのタグはfuzzuf.<親プロセスのPID>.<自身のPID>.<tagで指定した値>になる
 * この関数はログの送信が完了するか失敗するまでブロックする
 * @brief ログを送信する
 * @param tag このログのタグを指定する
 * @param sync 同期送信を行うかどうかを指定する
 * @param message ログ
 * @return ログの送信の結果
 **/
status_t log(std::string &&tag, std::string &&message);
/**
 * init_loggerで設定された送信先にJSONのログを送る
 * ログのタグはfuzzuf.<親プロセスのPID>.<自身のPID>.<tagで指定した値>になる
 * この関数はログの送信を送信キューに積んで送信完了を待たずに返る
 * @brief ログを送信する
 * @param tag このログのタグを指定する
 * @param message ログ
 * @param cb ログの送信が完了または失敗した際に呼ばれるコールバック
 **/
void log(std::string &&tag, nlohmann::json &&message,
         std::function<void(status_t)> &&cb);
/**
 * init_loggerで設定された送信先にJSONのログを送る
 * ログのタグはfuzzuf.<親プロセスのPID>.<自身のPID>.<tagで指定した値>になる
 * この関数はログの送信が完了するか失敗するまでブロックする
 * @brief ログを送信する
 * @param tag このログのタグを指定する
 * @param sync 同期送信を行うかどうかを指定する
 * @param message ログ
 * @return ログの送信の結果
 **/
status_t log(std::string &&tag, nlohmann::json &&message);

};  // namespace fuzzuf::utils

#endif
