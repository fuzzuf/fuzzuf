/*
    For forkserver related parts, modified codes from AFL's QEMU mode (original
    license below).
    ---------------------------------------------------------------------
    Forkserver written and design by Michal Zalewski <lcamtuf@google.com>
    and Jann Horn <jannhorn@googlemail.com>

    Copyright 2013, 2014, 2015, 2016 Google Inc. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at:

      http://www.apache.org/licenses/LICENSE-2.0
*/

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <stdint.h>

#define COV_FORKSRV_FD      198
#define BR_FORKSRV_FD      194
#define FORK_WAIT_MULT  10

static pid_t coverage_forksrv_pid;
static int coverage_fsrv_ctl_fd, coverage_fsrv_st_fd;
static pid_t branch_forksrv_pid;
static int branch_fsrv_ctl_fd, branch_fsrv_st_fd;

static pid_t child_pid = 0;
static int timeout_flag;
static int non_fork_stdin_fd;
static int coverage_stdin_fd;
static int branch_stdin_fd;

void error_exit(char* msg) {
    perror(msg);
    exit(-1);
}

void set_env (char *env_variable, char *env_value) {
    setenv(env_variable, env_value, 1);
}

void unset_env (char *env_variable) {
    unsetenv(env_variable);
}

void open_stdin_fd(int * fd){

    unlink(".stdin");

    *fd = open(".stdin", O_RDWR | O_CREAT | O_EXCL, 0600);

    if (*fd == -1)
        error_exit("open_stdin_fd : failed to open");

    /* If the descriptor is leaked, program will consume all the file
     * descriptors up to *_FORKSRV_FD, which results in protocol error
     * between forkserver and its client.
     */
    if (*fd > COV_FORKSRV_FD - 10)
        error_exit("open_stdin_fd : detected a leak of file descriptor");
}

void write_stdin(int stdin_fd, int stdin_size, char* stdin_data) {
    lseek(stdin_fd, 0, SEEK_SET);

    if(write(stdin_fd, stdin_data, stdin_size) != stdin_size)
        error_exit("write_stdin");

    if(ftruncate(stdin_fd, stdin_size))
        error_exit("ftruncate");

    lseek(stdin_fd, 0, SEEK_SET);
}

static void alarm_callback(int sig) {

    if (child_pid) {
        puts("Timeout");
        fflush(stdout);
        /* If we are in fuzzing mode, send SIGTERM (not SIGKILL) so that QEMU
         * tracer can receive it and call eclipser_exit() to finish logging.
         */
        kill(child_pid, SIGTERM);
        timeout_flag = 1;
        /* In some cases, the child process may not be terminated by the code
         * above, so examine if process is alive and send SIGKILL if so. */
        usleep(400 * 1000); // Give 400ms for SIGTERM handling
        if ( kill(child_pid, 0) == 0)
          kill(child_pid, SIGKILL);
    }
}

void initialize_exec(void) {
    struct sigaction sa;
    //void* handle = dlopen("libutil.so.1", RTLD_LAZY);

    sa.sa_flags     = SA_RESTART;
    sa.sa_sigaction = NULL;

    sigemptyset(&sa.sa_mask);

    sa.sa_handler = alarm_callback;
    sigaction(SIGALRM, &sa, NULL);
}


int waitchild(pid_t pid, uint64_t timeout)
{
    int childstatus = 0;

    if (timeout >= 1000)
        alarm(timeout/1000);
    else
        ualarm(timeout*1000, 0);

    if ( waitpid(pid, &childstatus, 0) < 0)
      perror("[Warning] waitpid() : ");

    alarm(0); // Cancle pending alarm

    if ( WIFEXITED( childstatus ) ) return 0;

    if ( WIFSIGNALED( childstatus ) ) {
        if ( WTERMSIG( childstatus ) == SIGSEGV ) return SIGSEGV;
        else if ( WTERMSIG( childstatus ) == SIGFPE ) return SIGFPE;
        else if ( WTERMSIG( childstatus ) == SIGILL ) return SIGILL;
        else if ( WTERMSIG( childstatus ) == SIGABRT ) return SIGABRT;
        else if ( timeout_flag ) return SIGALRM;
        else return 0;
    } else {
        return 0;
    }
}


int exec(int argc, char **args, int stdin_size, char *stdin_data, uint64_t timeout) {
    int i, devnull, ret;
    char **argv = (char **)malloc(sizeof(char*) * (argc + 1));

    if (!argv) error_exit( "args malloc" );

    for (i = 0; i<argc; i++) {
        argv[i] = args[i];
    }
    argv[i] = 0;

    child_pid = fork();
    if (child_pid == 0) {
        devnull = open("/dev/null", O_RDWR);
        if ( devnull < 0 ) error_exit("devnull open");
        dup2(devnull, 1);
        dup2(devnull, 2);
        close(devnull);

        open_stdin_fd(&non_fork_stdin_fd);
        write_stdin(non_fork_stdin_fd, stdin_size, stdin_data);
        dup2(non_fork_stdin_fd, 0);
        // We already wrote stdin_data and redirected it, so OK to close
        close(non_fork_stdin_fd);

        execv(argv[0], argv);
        exit(-1);
    } else if (child_pid > 0) {
        free(argv);
    } else {
        error_exit("fork");
    }

    timeout_flag = 0; // Reset timeout_flag

    return waitchild(child_pid, timeout);
}

pid_t init_forkserver(int argc, char** args, uint64_t timeout, int forksrv_fd,
                      int *stdin_fd, int *fsrv_ctl_fd, int *fsrv_st_fd) {
    static struct itimerval it;
    int st_pipe[2], ctl_pipe[2];
    int status;
    int devnull, i;
    int32_t rlen;
    pid_t forksrv_pid;
    char **argv = (char **)malloc( sizeof(char*) * (argc + 1) );

    open_stdin_fd(stdin_fd);

    if (!argv) error_exit( "args malloc" );
    for (i = 0; i<argc; i++)
        argv[i] = args[i];
    argv[i] = 0;

    if (pipe(st_pipe) || pipe(ctl_pipe)) error_exit("pipe() failed");

    forksrv_pid = fork();

    if (forksrv_pid < 0) error_exit("fork() failed");

    if (!forksrv_pid) {

        struct rlimit r;

        if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < COV_FORKSRV_FD + 2) {
          r.rlim_cur = COV_FORKSRV_FD + 2;
          setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
        }

        r.rlim_max = r.rlim_cur = 0;

        setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

        setsid();

        devnull = open( "/dev/null", O_RDWR );
        if ( devnull < 0 ) error_exit( "devnull open" );
        dup2(devnull, 1);
        dup2(devnull, 2);
        close(devnull);

        dup2(*stdin_fd, 0);

      if (dup2(ctl_pipe[0], forksrv_fd) < 0) error_exit("dup2() failed");
      if (dup2(st_pipe[1], forksrv_fd + 1) < 0) error_exit("dup2() failed");

      close(ctl_pipe[0]);
      close(ctl_pipe[1]);
      close(st_pipe[0]);
      close(st_pipe[1]);

      setenv("LD_BIND_NOW", "1", 0);

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "symbolize=0:"
                             "allocator_may_return_null=1", 0);

      execv(argv[0], argv);

      exit(0);
    }
    free(argv);

    close(ctl_pipe[0]);
    close(st_pipe[1]);

    *fsrv_ctl_fd = ctl_pipe[1];
    *fsrv_st_fd  = st_pipe[0];

    it.it_value.tv_sec = (timeout * FORK_WAIT_MULT) / 1000;
    it.it_value.tv_usec = ((timeout * FORK_WAIT_MULT) % 1000) * 1000;

    setitimer(ITIMER_REAL, &it, NULL);

    rlen = read(*fsrv_st_fd, &status, 4);

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;

    setitimer(ITIMER_REAL, &it, NULL);

    if (rlen == 4) {
      return forksrv_pid;
    }

    if (timeout_flag) {
      perror("Timeout while initializing fork server");
      return -1;
    }

    if (waitpid(forksrv_pid, &status, 0) <= 0) {
      perror("waitpid() failed while initializing fork server");
      return -1;
    }

    perror("Fork server died");
    return -1;
}

pid_t init_forkserver_coverage(int argc, char** args, uint64_t timeout) {
    coverage_forksrv_pid = init_forkserver(argc, args, timeout, COV_FORKSRV_FD,
                                          &coverage_stdin_fd,
                                          &coverage_fsrv_ctl_fd,
                                          &coverage_fsrv_st_fd);
    return coverage_forksrv_pid;
}

pid_t init_forkserver_branch(int argc, char** args, uint64_t timeout) {
    branch_forksrv_pid = init_forkserver(argc, args, timeout, BR_FORKSRV_FD,
                                         &branch_stdin_fd,
                                         &branch_fsrv_ctl_fd,
                                         &branch_fsrv_st_fd);
    return branch_forksrv_pid;
}

void kill_forkserver() {

    close(coverage_stdin_fd);
    close(branch_stdin_fd);

    close(coverage_fsrv_ctl_fd);
    close(coverage_fsrv_st_fd);
    close(branch_fsrv_ctl_fd);
    close(branch_fsrv_st_fd);

    if (coverage_forksrv_pid) {
        kill(coverage_forksrv_pid, SIGKILL);
        coverage_forksrv_pid = 0;
    }
    if (branch_forksrv_pid) {
        kill(branch_forksrv_pid, SIGKILL);
        branch_forksrv_pid = 0;
    }
}

int exec_fork_coverage(uint64_t timeout, int stdin_size, char *stdin_data) {
    int res, childstatus;
    static struct itimerval it;
    static unsigned char tmp[4];

    write_stdin(coverage_stdin_fd, stdin_size, stdin_data);

    if ((res = write(coverage_fsrv_ctl_fd, tmp, 4)) != 4) {
      perror("exec_fork_coverage: Cannot request new process to fork server");
      printf("write() call ret = %d\n", res);
      return -1;
    }

    if ((res = read(coverage_fsrv_st_fd, &child_pid, 4)) != 4) {
      perror("exec_fork_coverage: Cannot receive child pid from fork server");
      printf("read() call ret = %d, child_pid = %d\n", res, child_pid);
      return -1;
    }

    if (child_pid <= 0) {
      perror("exec_fork_coverage: Fork server is mibehaving");
      return -1;
    }

    it.it_value.tv_sec = (timeout / 1000);
    it.it_value.tv_usec = (timeout % 1000) * 1000;
    setitimer(ITIMER_REAL, &it, NULL);

    if ((res = read(coverage_fsrv_st_fd, &childstatus, 4)) != 4) {
      perror("exec_fork_coverage: Unable to communicate with fork server");
      printf("read() call ret = %d, childstatus = %d\n", res, childstatus);
      return -1;
    }

    if (!WIFSTOPPED(childstatus)) child_pid = 0;

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);

    if ( WIFEXITED( childstatus ) ) return 0;

    if ( WIFSIGNALED( childstatus ) ) {
        if ( WTERMSIG( childstatus ) == SIGSEGV ) return SIGSEGV;
        else if ( WTERMSIG( childstatus ) == SIGFPE ) return SIGFPE;
        else if ( WTERMSIG( childstatus ) == SIGILL ) return SIGILL;
        else if ( WTERMSIG( childstatus ) == SIGABRT ) return SIGABRT;
        else if ( timeout_flag ) return SIGALRM;
        else return 0;
    } else {
        return 0;
    }
}

int exec_fork_branch(uint64_t timeout, int stdin_size, char *stdin_data,
                     uint64_t targ_addr, uint32_t targ_index, int measure_cov) {
    int res, childstatus;
    static struct itimerval it;

    /* TODO : what if we want to use pseudo-terminal? */
    write_stdin(branch_stdin_fd, stdin_size, stdin_data);

    if ((res = write(branch_fsrv_ctl_fd, &targ_addr, 8)) != 8) {
      perror("exec_fork_branch: Cannot send targ_addr to fork server");
      printf("write() call ret = %d\n", res);
      return -1;
    }

    if ((res = write(branch_fsrv_ctl_fd, &targ_index, 4)) != 4) {
      perror("exec_fork_branch: Cannot send targ_index to fork server");
      printf("write() call ret = %d\n", res);
      return -1;
    }

    if ((res = write(branch_fsrv_ctl_fd, &measure_cov, 4)) != 4) {
      perror("exec_fork_branch: Cannot send measure_cov to fork server");
      printf("write() call ret = %d\n", res);
      return -1;
    }

    if ((res = read(branch_fsrv_st_fd, &child_pid, 4)) != 4) {
      perror("exec_fork_branch: Cannot receive child pid from fork server");
      printf("read() call ret = %d, child_pid = %d\n", res, child_pid);
      return -1;
    }

    if (child_pid <= 0) {
      perror("exec_fork_branch: Fork server is mibehaving");
      return -1;
    }

    it.it_value.tv_sec = (timeout / 1000);
    it.it_value.tv_usec = (timeout % 1000) * 1000;
    setitimer(ITIMER_REAL, &it, NULL);

    if ((res = read(branch_fsrv_st_fd, &childstatus, 4)) != 4) {
      perror("exec_fork_branch: Unable to communicate with fork server");
      printf("read() call ret = %d, childstatus = %d\n", res, childstatus);
      return -1;
    }

    if (!WIFSTOPPED(childstatus)) child_pid = 0;

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);

    if ( WIFEXITED( childstatus ) ) return 0;

    if ( WIFSIGNALED( childstatus ) ) {
        if ( WTERMSIG( childstatus ) == SIGSEGV ) return SIGSEGV;
        else if ( WTERMSIG( childstatus ) == SIGFPE ) return SIGFPE;
        else if ( WTERMSIG( childstatus ) == SIGILL ) return SIGILL;
        else if ( WTERMSIG( childstatus ) == SIGABRT ) return SIGABRT;
        else if ( timeout_flag ) return SIGALRM;
        else return 0;
    } else {
        return 0;
    }
}

#pragma GCC diagnostic pop

