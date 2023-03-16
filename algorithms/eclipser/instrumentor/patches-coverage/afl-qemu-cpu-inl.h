/*
    Modified codes from AFL's QEMU mode (original license below).
    -----------------------------------------------------------------

    Written by Andrew Griffiths <agriffiths@google.com> and
               Michal Zalewski <lcamtuf@google.com>

    Idea & design very much by Andrew Griffiths.

    Copyright 2015, 2016 Google Inc. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at:

      http://www.apache.org/licenses/LICENSE-2.0
*/

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

#define FORKSRV_FD 198
#define TSL_FD (FORKSRV_FD - 1)

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Function declarations. */

static void afl_forkserver(CPUState*);

static void afl_wait_tsl(CPUState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t,
                            TranslationBlock*, int);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
  int chained;
};

struct afl_chain {
  target_ulong last_pc;
  target_ulong last_cs_base;
  uint64_t last_flags;
  int tb_exit;
};

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUState *cpu) {

  static unsigned char tmp[4];

  if (atoi(getenv("ECL_FORK_SERVER")) != 1) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}

/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags,
                            TranslationBlock* last_tb, int tb_exit)  {
  struct afl_tsl t;
  struct afl_chain c;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;
  t.chained = (last_tb != NULL);

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

  if (last_tb) {
    c.last_pc      = last_tb->pc;
    c.last_cs_base = last_tb->cs_base;
    c.last_flags   = last_tb->flags;
    c.tb_exit      = tb_exit;

    if (write(TSL_FD, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
      return;
  }
}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  struct afl_chain c;
  TranslationBlock *tb, *last_tb;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);

    if(!tb) {
      mmap_lock();
      tb_lock();
      tb = tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
      mmap_unlock();
      tb_unlock();
    }

    if (t.chained) {
      if (read(fd, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
        break;

      last_tb = tb_htable_lookup(cpu, c.last_pc, c.last_cs_base, c.last_flags);
      if (last_tb) {
        tb_lock();
        if (!tb->invalid) {
          tb_add_jump(last_tb, c.tb_exit, tb);
        }
        tb_unlock();
      }
    }
  }

  close(fd);

}
