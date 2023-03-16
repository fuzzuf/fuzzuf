#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "qemu/osdep.h"

#ifdef TARGET_X86_64
typedef uint64_t abi_ulong;
#else
typedef uint32_t abi_ulong;
#endif

extern unsigned int afl_forksrv_pid;
#define FORKSRV_FD 198
#define TSL_FD (FORKSRV_FD - 1)

#define BITMAP_SIZE (0x10000)
#define BITMAP_MASK (BITMAP_SIZE - 1)

void eclipser_setup_before_forkserver(void);
void eclipser_setup_after_forkserver(void);
void eclipser_detach(void);
void eclipser_exit(void);
void helper_eclipser_log_bb(abi_ulong addr);

abi_ulong eclipser_entry_point; /* ELF entry point (_start) */

static char * coverage_path = NULL;
static char * dbg_path = NULL;
static FILE * coverage_fp = NULL;
static FILE * dbg_fp = NULL;

static abi_ulong prev_addr = 0;
static int found_new_edge = 0;
static int found_new_path = 0; // TODO. Extend to measure path coverage, too.
static unsigned char * edge_bitmap = NULL;

void eclipser_setup_before_forkserver(void) {
  char * bitmap_path = getenv("ECL_BITMAP_LOG");
  int bitmap_fd = open(bitmap_path, O_RDWR | O_CREAT, 0644);
  edge_bitmap = (unsigned char*) mmap(NULL, BITMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, bitmap_fd, 0);
  assert(edge_bitmap != (void *) -1);

  coverage_path = getenv("ECL_COVERAGE_LOG");
  dbg_path = getenv("ECL_DBG_LOG");
}

void eclipser_setup_after_forkserver(void) {
  /* Open file pointers and descriptors early, since if we try to open them in
   * eclipser_exit(), it gets mixed with stderr & stdout stream. This seems to
   * be an issue due to incorrect file descriptor management in QEMU code.
   */

  coverage_fp = fopen(coverage_path, "w");
  assert(coverage_fp != NULL);

  /* In dbg_path is not NULL, open the file for debug message logging. */
  if(dbg_path != NULL) {
    dbg_fp = fopen(dbg_path, "w");
    assert(dbg_fp != NULL);
  }
}

// When fork() syscall is encountered, child process should call this function
// to detach from Eclipser.
void eclipser_detach(void) {
  // Close file pointers, to avoid dumping log twice.
  if (coverage_fp) {
    fclose(coverage_fp);
    coverage_fp = NULL;
  }

  if (dbg_fp) {
    fclose(dbg_fp);
    dbg_fp = NULL;
  }

  if (edge_bitmap) {
    munmap(edge_bitmap, BITMAP_SIZE);
    edge_bitmap = NULL;
  }

  if (afl_forksrv_pid)
    close(TSL_FD);
}

void eclipser_exit(void) {
  sigset_t mask;

  // Block signals, since we register signal handler that calls eclipser_exit()/
  if (sigfillset(&mask) < 0)
    return;
  if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
    return;

  if (coverage_fp) {
    fprintf(coverage_fp, "%d\n%d\n", found_new_edge, found_new_path);
    fclose(coverage_fp);
    coverage_fp = NULL;
  }

  if (dbg_fp) {
    fclose(dbg_fp);
    dbg_fp = NULL;
  }

  if (edge_bitmap) {
    munmap(edge_bitmap, BITMAP_SIZE);
    edge_bitmap = NULL;
  }
}

void helper_eclipser_log_bb(abi_ulong addr) {
  abi_ulong prev_addr_local;
  abi_ulong edge, hash;
  unsigned int byte_idx, byte_mask;
  unsigned char old_byte, new_byte;

  // Make sure that 'prev_addr' is always updated even if we just return.
  prev_addr_local = prev_addr;
  prev_addr = addr;

  if (!coverage_fp || !edge_bitmap)
    return;

#ifdef TARGET_X86_64
  edge = (prev_addr_local << 16) ^ addr;
#else
  edge = (prev_addr_local << 8) ^ addr;
#endif

  // Update bitmap.
  hash = (edge >> 4) ^ (edge << 8);
  byte_idx = (hash >> 3) & BITMAP_MASK;
  byte_mask = 1 << (hash & 0x7); // Use the lowest 3 bits to shift
  old_byte = edge_bitmap[byte_idx];
  new_byte = old_byte | byte_mask;
  if (old_byte != new_byte) {
    found_new_edge = 1;
    edge_bitmap[byte_idx] = new_byte;
    /* Log visited nodes if dbg_fp is not NULL */
    if (dbg_fp) {
#ifdef TARGET_X86_64
      fprintf(dbg_fp, "(0x%lx)\n", addr);
#else
      fprintf(dbg_fp, "(0x%x)\n", addr);
#endif
    }
  }
}
