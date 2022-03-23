#include "fuzzuf/cli/setup_execution_environment.hpp"

#include <signal.h>
#include <cstddef>

namespace fuzzuf::cli {

// NOTE: Only supports Linux
void SetupExecutionEnvironment() {
    struct sigaction sa;

    sa.sa_handler = NULL;
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = NULL;

    sigemptyset(&sa.sa_mask);

    /* Things we don't care about. */

    sa.sa_handler = SIG_IGN;
    sigaction(SIGTSTP, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
}

}
