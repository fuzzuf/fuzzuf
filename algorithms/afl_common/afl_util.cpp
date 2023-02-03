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
#include "fuzzuf/algorithms/afl/afl_util.hpp"

#include <random>

#include "fuzzuf/algorithms/afl/afl_macro.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"

// A temporary criteria for deciding whether to put new utils here or make them
// class member functions:
//     - AFL-specific utility functions that may be useful to implement
//     AFL-derived algorithms should be added here
//     - However, place them where appropriate other than here if such
//     algorithms may change their implementations
//       to change the behavior (e.g. implement them as AFLState's member
//       functions and make them inheritable).
//     - Basically, utilities having large side-effects (e.g. modifying the
//     state) should not be placed here
//        * Rather, it should be AFLState's member function
//        * Yet, it does not apply to functions need to be called from multiple
//        classes (e.g. RetryCalibrate and SaveIfInteresting)
//          * The advantage of implementing a utility here is that side-effects
//          can be observed clearly since it is not
//            referenced through member variables but always through arguments

namespace fuzzuf::algorithm::afl::util {

u32 UR(u32 limit, int rand_fd) {
  static u32 rand_cnt;
  if (rand_fd != -1 && unlikely(!rand_cnt--)) {
    u32 seed[2];
    fuzzuf::utils::ReadFile(rand_fd, &seed, sizeof(seed));
    srandom(seed[0]);

    using option::AFLTag;
    using option::GetReseedRng;
    rand_cnt =
        (GetReseedRng<AFLTag>() / 2) + (seed[1] % GetReseedRng<AFLTag>());
  }
  return random() % limit;
}

/* Describe all the integers with five characters or less */

std::string DescribeInteger(u64 val) {
#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast)                  \
  do {                                                                  \
    if (val < (_divisor) * (_limit_mult)) {                             \
      return fuzzuf::utils::StrPrintf(_fmt, ((_cast)val) / (_divisor)); \
    }                                                                   \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  return "infty";
}

/* Describe float. Similar to the above, except with a single
   static buffer. */

std::string DescribeFloat(double val) {
  if (val < 99.995) {
    return fuzzuf::utils::StrPrintf("%0.02f", val);
  }

  if (val < 999.95) {
    return fuzzuf::utils::StrPrintf("%0.01f", val);
  }

  return DescribeInteger((u64)val);
}

std::string DescribeMemorySize(u64 val) {
  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  return "infty";
}

/* Describe time delta. Returns one static buffer, 34 chars of less. */

std::string DescribeTimeDelta(u64 cur_ms, u64 event_ms) {
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) return "none seen yet";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  return fuzzuf::utils::StrPrintf("%s days, %u hrs, %u min, %u sec",
                                  DescribeInteger(t_d).c_str(), t_h, t_m, t_s);
}

}  // namespace fuzzuf::algorithm::afl::util
