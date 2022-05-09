#include <boost/scope_exit.hpp>
#include <cstdlib>
#include <fuzzuf/logger/logger.hpp>
#include <fuzzuf/utils/check_crash_handling.hpp>

namespace fuzzuf::utils {

void CheckCrashHandling() {
#ifdef __APPLE__

#if !TARGET_OS_IPHONE
  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'")) return;

  MSG("\n" cLRD "[-] " cRST
      "Whoops, your system is configured to forward crash notifications to an\n"
      "    external crash reporting utility. This will cause issues due to "
      "the\n"
      "    extended delay between the fuzzed binary malfunctioning and this "
      "fact\n"
      "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
      "    To avoid having crashes misinterpreted as timeouts, please run the\n"
      "    following commands:\n\n"

      "    SL=/System/Library; PL=com.apple.ReportCrash\n"
      "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
      "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

#endif
  if (!get_afl_env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES")) {
    ERROR("Crash reporter detected");
    __builtin_unreachable();
  }

#else
  int fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  BOOST_SCOPE_EXIT(&fd) { close(fd); }
  BOOST_SCOPE_EXIT_END
  char fchar = '\0';

  if (fd < 0) {
    return;
  }

  MSG(cLBL "[*] " cRST "Checking core_pattern...\n");

  if (read(fd, &fchar, sizeof(fchar)) == sizeof(fchar) && fchar == '|') {
    MSG("\n" cLRD "[-] " cRST
        "Hmm, your system is configured to send core dump notifications to an\n"
        "    external utility. This will cause issues: there will be an "
        "extended delay\n"
        "    between stumbling upon a crash and having this information "
        "relayed to the\n"
        "    fuzzer via the standard waitpid() API.\n"
        "    If you're just testing, set "
        "'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1'.\n\n"

        "    To avoid having crashes misinterpreted as timeouts, please log in "
        "as root\n"
        "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

        "    echo core >/proc/sys/kernel/core_pattern\n");

    if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES")) {
      ERROR("Pipe at the beginning of 'core_pattern'");
      __builtin_unreachable();
    }
  }
#endif
}

}  // namespace fuzzuf::utils
