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
 * @file update_hierarflow_routines.cpp
 * @brief Definition of HierarFlow routines of Nautilus state update.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/fuzzer/update_hierarflow_routines.hpp"

#include <sys/ioctl.h>

#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer::routine::update {

/* Constants */
constexpr const char BANNER[] = "fuzzuf nautilus mode";
constexpr const char VERSION[] = "2.0";
constexpr u32 GetUiTargetHz() { return 5; }

/**
 * @fn
 * @brief Check if terminal size is too small
 * @return True if terminal is too small, otherwise false
 */
static bool CheckTermSize() {
  struct winsize ws;

  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws)) {
    return false;
  } else if (ws.ws_row == 0 && ws.ws_col == 0) {
    return false;
  } else if (ws.ws_row < 25 || ws.ws_col < 80) {
    return true;
  } else {
    return false;
  }
}

/**
 * @fn
 * @brief HierarFlow routine for UpdateState (update_state)
 */
RUpdateState UpdateState::operator()(void) {
  // TODO: Lock state when multi-threaded

  /* Check terminal size */
  if (CheckTermSize()) {
    MSG(cBRI
        "Your terminal is too small to display the UI.\n"
        "Please resize terminal window to at least 80x25.\n" cRST);

    return GoToDefaultNext();
  }

  using namespace std::chrono;
  using day_t = duration<long, std::ratio<3600 * 24>>;

  /* Calculate elapsed time */
  const system_clock::time_point current_time(system_clock::now());
  double elapsed =
      duration_cast<milliseconds>(current_time - state.last_time).count();

  /* Get current time */
  const std::time_t t = system_clock::to_time_t(state.start_time);
  const std::tm* tm = std::localtime(&t);
  std::ostringstream tmoss;
  tmoss << std::put_time(tm, "[%Y-%m-%d] %H:%M:%S");
  std::string str_start_time = tmoss.str();

  /* If not enough time has passed since last UI update, bail out.*/
  if (elapsed < 1000 / GetUiTargetHz()) {
    return GoToDefaultNext();
  }

  /* Check if we're past the 10 minute mark. */
  // bool run_over10m = elapsed > 10 * 60 * 1000;

  std::ostringstream oss;

  /* Clear terminal */
  oss << TERM_HOME;

  /* Title */
  u32 banner_len = strlen(BANNER) + 1 + strlen(VERSION) + 1 +
                   state.setting->banner_filename.size() + 2;
  u32 banner_pad = (80 - banner_len) / 2;
  oss << std::string(banner_pad, ' ') << cYEL << BANNER << " " << cLCY
      << VERSION << " " << cLGN << "(" << state.setting->banner_filename
      << ")\n\n";

  /* Process timing and overall results */
  oss << SET_G1 bSTG bLT bH bSTOP cCYA << " process timing "
      << bSTG bH30 bH2 bH2 bHB bH bSTOP cCYA << " overall results "
      << bSTG bH2 bH2 bRT "\n";

  auto run_time = current_time - state.start_time;
  auto d = duration_cast<day_t>(run_time);
  auto h = duration_cast<hours>(run_time -= d);
  auto m = duration_cast<minutes>(run_time -= h);
  auto s = duration_cast<seconds>(run_time -= m);
  oss << bV bSTOP "     run time : " cRST << std::right << std::setfill('0')
      << std::setw(4) << d.count() << " days, " << std::setw(2) << h.count()
      << " hrs, " << std::setw(2) << m.count() << " min, " << std::setw(2)
      << s.count() << " sec  " << bSTG bV bSTOP " cycles done : " cRST
      << std::left << std::setfill(' ') << std::setw(5);
  if (state.cycles_done < 1000) {
    oss << state.cycles_done << " ";
  } else {
    /* If more than one thousand, use kilo as unit */
    oss << std::setprecision(2)
        << static_cast<double>(state.cycles_done) / 1000.0 << "k";
  }
  oss << " " bSTG bV "\n";
  oss << bV bSTOP "   start time : " cRST << std::setw(35) << str_start_time
      << bSTG bV bSTOP " total execs : " cRST << std::setw(5);
  if (state.execution_count < 1000) {
    oss << state.execution_count << " ";
  } else {
    /* If more than one thousand, use kilo as unit */
    oss << std::setprecision(2)
        << static_cast<double>(state.execution_count) / 1000.0 << "k";
  }
  oss << " " bSTG bV "\n";
  oss << bV bSTOP "     last sig : " cRST << std::setw(35)
      << state.last_found_sig << bSTG bV bSTOP "        sigs : "
      << (state.total_found_sig ? cLRD : cRST) << std::setw(5)
      << state.total_found_sig << "  " bSTG bV "\n";
  oss << bV bSTOP "    last asan : " cRST << std::left << std::setw(35)
      << state.last_found_asan << bSTG bV bSTOP "       asans : "
      << (state.total_found_asan ? cLRD : cRST) << std::setw(5)
      << state.total_found_asan << "  " bSTG bV "\n";
  oss << bV bSTOP "    last hang : " cRST << std::left << std::setw(35)
      << state.last_timeout << bSTG bV bSTOP "       hangs : "
      << (state.total_found_hang ? cLRD : cRST) << std::setw(5)
      << state.total_found_hang << "  " bSTG bV "\n";
  oss << bV bSTOP "   exec speed : " cRST << std::left << std::setw(8)
      << state.average_executions_per_sec << "exec/sec  ";
  if (state.average_executions_per_sec < 100) {
    /* Check execution speed */
    if (state.average_executions_per_sec < 20) {
      oss << cLRD << "(zzzz...)" << cRST << std::string(8, ' ');
    } else {
      oss << cLRD << "(slow!)" << cRST << std::string(10, ' ');
    }
  } else {
    oss << std::string(17, ' ');
  }
  oss << bSTG bV bSTOP << std::string(22, ' ') << bSTG bV "\n";

  /* Strategy yields */
  oss << bVR bH bSTOP cCYA " bits found "
      << bSTG bH30 bH5 bH2 bH bHT bH20 bH2 bVL "\n";
  oss << bV bSTOP "     bits found by havoc : " cRST << std::setw(20)
      << state.bits_found_by_havoc << std::string(27, ' ') << bSTG bV "\n";
  oss << bV bSTOP " bits found by havoc rec : " cRST << std::setw(20)
      << state.bits_found_by_havoc_rec << std::string(27, ' ') << bSTG bV "\n";
  oss << bV bSTOP "       bits found by min : " cRST << std::setw(20)
      << state.bits_found_by_min << std::string(27, ' ') << bSTG bV "\n";
  oss << bV bSTOP "   bits found by min rec : " cRST << std::setw(20)
      << state.bits_found_by_min_rec << std::string(27, ' ') << bSTG bV "\n";
  oss << bV bSTOP "    bits found by splice : " cRST << std::setw(20)
      << state.bits_found_by_splice << std::string(27, ' ') << bSTG bV "\n";
  oss << bV bSTOP "       bits found by det : " cRST << std::setw(20)
      << state.bits_found_by_det << std::string(27, ' ') << bSTG bV "\n";
  oss << bV bSTOP "       bits found by gen : " cRST << std::setw(20)
      << state.bits_found_by_gen << std::string(27, ' ') << bSTG bV "\n";

  oss << bSTG bLB bH30 bH20 bH20 bH2 bH2 bRB bSTOP "\n";
  oss << cRST;

  MSG("%s\n", oss.str().c_str());

  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::update
