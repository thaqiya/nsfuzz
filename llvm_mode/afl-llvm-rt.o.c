/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This code is the rewrite of afl-as.h's main_payload.
*/

#include "../android-ashmem.h"
#include "../config.h"
#include "../types.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;
u8  __afl_area_data_initial[MAP_SIZE];
u8* __afl_area_data_ptr = __afl_area_data_initial;
u8  __afl_area_sv_range[SV_CNT * MAP_SIZE];
u8* __afl_area_sv_range_ptr = __afl_area_sv_range;
u8 session_virgin_bits[MAP_SIZE];
FILE *fp_debug;

__thread u32 __afl_prev_loc;


/* Running in persistent mode? */

static u8 is_persistent;

#ifdef DEBUG
void _log_debug(FILE *fp, const char *format, ...) {
    char time_string[40];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_now;
    tm_now = localtime(&(tv.tv_sec));
    strftime(time_string, sizeof(time_string), "[%Y-%m-%d %H:%M:%S", tm_now);

    fprintf(fp, "%s.%ld] ", time_string, tv.tv_usec);

    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    fflush(fp);
}
#else
void _log_debug(FILE *fp, const char *format, ...) {}
#endif
/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

  if (getenv("NET_FORKSERV")) {

    u8 *state_id_str = getenv(SHM_STATE_VAR);

    if (state_id_str) {

      u32 shm_state_id = atoi(state_id_str);

      __afl_area_data_ptr = shmat(shm_state_id, NULL, 0);

      if (__afl_area_data_ptr == (void *)-1)

        _exit(1);

      /* Write something into the bitmap so that even with low AFL_INST_RATIO,
        our parent doesn't give up on us. */
      // __afl_area_data_ptr[0] = 1;
    }
  }

	u8 *state_range_id_str = getenv(SHM_STATE_RANGE_VAR);
	if (state_range_id_str) {
		u32 shm_state_range_id = atoi(state_range_id_str);
		__afl_area_sv_range_ptr = shmat(shm_state_range_id, NULL, 0);
		if (__afl_area_sv_range_ptr == (void *)-1) {
			_exit(1);
		}
	}
}

static inline u8 has_new_bits(u8* virgin_map) {

  u64* current = (u64*)__afl_area_ptr;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

  u8 ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  return ret;

}

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  
  s32 child_pid;

  // s32 child_status = -1;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  if (getenv("NET_FORKSERV")) is_persistent = 1;

  fp_debug = fopen("./debug.txt", "w+");

  _log_debug(fp_debug, "is_persistent: %d\n", is_persistent);

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */
    _log_debug(fp_debug, "[*] in perform loop ---------------------------------------\n");
    _log_debug(fp_debug, "[*] read was_killed from fuzzer\n");
    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race condition and afl-fuzz already issued SIGKILL, write off the old process. */
    _log_debug(fp_debug, "was killed: %d, child_stopped: %d\n", was_killed, child_stopped);
    if (child_stopped && was_killed == 1) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);
      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }
      _log_debug(fp_debug, "start a new child, child pid: %d\n", child_pid);
      
    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */
      _log_debug(fp_debug, "remain in stopped child, child pid: %d, was_killed: %d\n", child_pid, was_killed);

      // one packet may contain multi delimma, which would cause to sync-loss, so we send multi SIGCONT to force the sync.
      for (size_t i = 0; i < 10; i++) kill(child_pid, SIGCONT);

      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    _log_debug(fp_debug, "[*] write child_pid to inform the fuzzer\n");

    // if (child_status != -1) {
    //   status = child_status;
    //   _log_debug(fp_debug, "status from pass from child_status: %d\n", status);
    // } else {
    //   if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) _exit(1);
    //   _log_debug(fp_debug, "waitpid success, status: %d\n", status);
    // }
    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) _exit(1);
      _log_debug(fp_debug, "waitpid success, status: %d\n", status);

    // The last request was sent and child stopped but not be terminated
    if (was_killed == 2 && WIFSTOPPED(status)) {
      _log_debug(fp_debug, "have recv the last packet\n");
      int check = kill(child_pid, 0);
      while ((check == 0) || (errno != ESRCH)) {
        _log_debug(fp_debug, "not self terminated, resume process and kill it\n");
        memset(session_virgin_bits, 255, MAP_SIZE);
        if (WIFSTOPPED(status)) kill(child_pid, SIGCONT);
        while(1) {
          kill(child_pid, SIGCONT);
          if (!has_new_bits(session_virgin_bits)) break;
          _log_debug(fp_debug, "still has new bits\n");
        }
        kill(child_pid, SIGTERM); // may use SIGKILL in some case?
        if (waitpid(child_pid, &status, WUNTRACED) < 0) _exit(1);
        check = kill(child_pid, 0);
      }
    }

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);
    _log_debug(fp_debug, "[*] write child status to inform the fuzzer: %d\n", status);
  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}


/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}
