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

#include <string>

#include "fuzzuf/logger/log_file_logger.hpp"
#include "fuzzuf/logger/stdout_logger.hpp"
#include "fuzzuf/utils/common.hpp"

/*******************
 * Terminal colors *
 *******************/

#define USE_COLOR  // currently we enable color
#ifdef USE_COLOR

#define cBLK "\x1b[0;30m"
#define cRED "\x1b[0;31m"
#define cGRN "\x1b[0;32m"
#define cBRN "\x1b[0;33m"
#define cBLU "\x1b[0;34m"
#define cMGN "\x1b[0;35m"
#define cCYA "\x1b[0;36m"
#define cLGR "\x1b[0;37m"
#define cGRA "\x1b[1;90m"
#define cLRD "\x1b[1;91m"
#define cLGN "\x1b[1;92m"
#define cYEL "\x1b[1;93m"
#define cLBL "\x1b[1;94m"
#define cPIN "\x1b[1;95m"
#define cLCY "\x1b[1;96m"
#define cBRI "\x1b[1;97m"
#define cRST "\x1b[0m"

#define bgBLK "\x1b[40m"
#define bgRED "\x1b[41m"
#define bgGRN "\x1b[42m"
#define bgBRN "\x1b[43m"
#define bgBLU "\x1b[44m"
#define bgMGN "\x1b[45m"
#define bgCYA "\x1b[46m"
#define bgLGR "\x1b[47m"
#define bgGRA "\x1b[100m"
#define bgLRD "\x1b[101m"
#define bgLGN "\x1b[102m"
#define bgYEL "\x1b[103m"
#define bgLBL "\x1b[104m"
#define bgPIN "\x1b[105m"
#define bgLCY "\x1b[106m"
#define bgBRI "\x1b[107m"

#else

#define cBLK ""
#define cRED ""
#define cGRN ""
#define cBRN ""
#define cBLU ""
#define cMGN ""
#define cCYA ""
#define cLGR ""
#define cGRA ""
#define cLRD ""
#define cLGN ""
#define cYEL ""
#define cLBL ""
#define cPIN ""
#define cLCY ""
#define cBRI ""
#define cRST ""

#define bgBLK ""
#define bgRED ""
#define bgGRN ""
#define bgBRN ""
#define bgBLU ""
#define bgMGN ""
#define bgCYA ""
#define bgLGR ""
#define bgGRA ""
#define bgLRD ""
#define bgLGN ""
#define bgYEL ""
#define bgLBL ""
#define bgPIN ""
#define bgLCY ""
#define bgBRI ""

#endif /* ^USE_COLOR */

/*************************
 * Box drawing sequences *
 *************************/

#define FANCY_BOXES
#ifdef FANCY_BOXES

#define SET_G1 "\x1b)0"   /* Set G1 for box drawing    */
#define RESET_G1 "\x1b)B" /* Reset G1 to ASCII         */
#define bSTART "\x0e"     /* Enter G1 drawing mode     */
#define bSTOP "\x0f"      /* Leave G1 drawing mode     */
#define bH "q"            /* Horizontal line           */
#define bV "x"            /* Vertical line             */
#define bLT "l"           /* Left top corner           */
#define bRT "k"           /* Right top corner          */
#define bLB "m"           /* Left bottom corner        */
#define bRB "j"           /* Right bottom corner       */
#define bX "n"            /* Cross                     */
#define bVR "t"           /* Vertical, branch right    */
#define bVL "u"           /* Vertical, branch left     */
#define bHT "v"           /* Horizontal, branch top    */
#define bHB "w"           /* Horizontal, branch bottom */

#else

#define SET_G1 ""
#define RESET_G1 ""
#define bSTART ""
#define bSTOP ""
#define bH "-"
#define bV "|"
#define bLT "+"
#define bRT "+"
#define bLB "+"
#define bRB "+"
#define bX "+"
#define bVR "+"
#define bVL "+"
#define bHT "+"
#define bHB "+"

#endif /* ^FANCY_BOXES */

/* "Handy" shortcuts for drawing boxes... */
#define bSTG bSTART cGRA
#define bH2 bH bH
#define bH5 bH2 bH2 bH
#define bH10 bH5 bH5
#define bH20 bH10 bH10
#define bH30 bH20 bH10
#define SP5 "     "
#define SP10 SP5 SP5
#define SP20 SP10 SP10

/***********************
 * Misc terminal codes *
 ***********************/

#define TERM_HOME "\x1b[H"
#define TERM_CLEAR TERM_HOME "\x1b[2J"
#define cEOL "\x1b[0K"
#define CURSOR_HIDE "\x1b[?25l"
#define CURSOR_SHOW "\x1b[?25h"

namespace fuzzuf::utils {

enum Logger {
  Stdout,
  LogFile,
  Flc,  // 将来対応予定？
};

std::string to_string(Logger v);

enum RunLevel {
  MODE_RELEASE,
  MODE_DEBUG,
};

extern RunLevel runlevel;

}  // namespace fuzzuf::utils

#define MSG(...) std::printf(__VA_ARGS__)
#define FUZZUF_FORMAT(temp, ...)                                 \
  {                                                              \
    temp.assign(4000, ' ');                                      \
    auto size = snprintf(temp.data(), temp.size(), __VA_ARGS__); \
    temp.resize(size);                                           \
    temp.shrink_to_fit();                                        \
  }

#define IS_DEBUG_MODE() \
  (fuzzuf::utils::runlevel >= fuzzuf::utils::RunLevel::MODE_DEBUG)
#define DEBUG(...)                                                          \
  {                                                                         \
    if (fuzzuf::utils::runlevel >= fuzzuf::utils::RunLevel::MODE_DEBUG ||   \
        ::fuzzuf::utils::has_logger()) {                                    \
      std::string temp;                                                     \
      FUZZUF_FORMAT(temp, __VA_ARGS__)                                      \
      if (fuzzuf::utils::runlevel >= fuzzuf::utils::RunLevel::MODE_DEBUG) { \
        fuzzuf::utils::StdoutLogger::Println(temp);                         \
        fuzzuf::utils::LogFileLogger::Println(temp);                        \
      }                                                                     \
      if (::fuzzuf::utils::has_logger())                                    \
        ::fuzzuf::utils::log("log.debug.debug",                             \
                             nlohmann::json({{"message", std::move(temp)},  \
                                             {"file", __FILE__},            \
                                             {"line", __LINE__}}),          \
                             [](auto) {});                                  \
    }                                                                       \
  }

/* Die with a verbose non-OS fatal error message. */

#define EXIT(...)                                                           \
  do {                                                                      \
    std::string temp;                                                       \
    FUZZUF_FORMAT(temp, __VA_ARGS__)                                        \
    MSG(bSTOP RESET_G1 cRST cLRD "\n[-] PROGRAM ABORT : " cBRI);            \
    std::puts(temp.c_str());                                                \
    MSG(cLRD "\n         Location : " cRST "%s(), %s:%u\n\n", __FUNCTION__, \
        __FILE__, __LINE__);                                                \
    if (::fuzzuf::utils::has_logger())                                      \
      ::fuzzuf::utils::log("log.error.exit",                                \
                           nlohmann::json({{"message", std::move(temp)},    \
                                           {"file", __FILE__},              \
                                           {"line", __LINE__}}));           \
    exit(1);                                                                \
  } while (0)

/* Die by calling abort() to provide a core dump. */

#define ABORT(...)                                                          \
  do {                                                                      \
    std::string temp;                                                       \
    FUZZUF_FORMAT(temp, __VA_ARGS__)                                        \
    MSG(bSTOP RESET_G1 cRST cLRD "\n[-] PROGRAM ABORT : " cBRI);            \
    std::puts(temp.c_str());                                                \
    MSG(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n\n", __FUNCTION__, \
        __FILE__, __LINE__);                                                \
    if (::fuzzuf::utils::has_logger())                                      \
      ::fuzzuf::utils::log("log.error.abort",                               \
                           nlohmann::json({{"message", std::move(temp)},    \
                                           {"file", __FILE__},              \
                                           {"line", __LINE__}}));           \
    abort();                                                                \
  } while (0)

/* Die while also including the output of perror(). */

#define ERROR(...)                                                        \
  {                                                                       \
    fflush(stdout);                                                       \
    std::string temp;                                                     \
    FUZZUF_FORMAT(temp, __VA_ARGS__)                                      \
    MSG(bSTOP RESET_G1 cRST cLRD "\n[-]  SYSTEM ERROR : " cBRI);          \
    std::puts(temp.c_str());                                              \
    MSG(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n", __FUNCTION__, \
        __FILE__, __LINE__);                                              \
    MSG(cLRD "       OS message : " cRST "%s\n", strerror(errno));        \
    if (::fuzzuf::utils::has_logger())                                    \
      ::fuzzuf::utils::log(                                               \
          "log.error.system_error",                                       \
          nlohmann::json({{"message", std::move(temp)},                   \
                          {"file", __FILE__},                             \
                          {"line", __LINE__},                             \
                          {"errno", errno},                               \
                          {"strerror", std::strerror(errno)}}));          \
    std::exit(1);                                                         \
  }
