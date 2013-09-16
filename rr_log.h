#ifndef RR_LOG_H
#define RR_LOG_H
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>

#include "rr_log_consts.h"

struct FILE;

struct rr_entry {
	uint8_t type;
	uint32_t eip;
  uint32_t ecx;
	uint64_t n_branches;
	uint64_t info;
  uint32_t ebufsize;
   uint8_t cpu;
  /*
  uint8_t rrdata[12];
  uint16_t rrport;
  uint16_t rrsize;
  __u64 vector1;
  __u64 vector2;
  __u64 dbg1;
  __u64 dbg2;
  __u64 start_brcount;
  __u64 stop_brcount;
  */
};

#define MAX_RR_BUF_SIZE 1024*1024
extern struct rr_entry replay_entry;
extern uint8_t replay_buf[MAX_RR_BUF_SIZE];
extern size_t replay_buf_size;
extern bool record_output_bdrv, replay_output_bdrv;


void output_rr_record(struct FILE *fp, struct rr_entry *entry, const void *buf);
void input_rr_record(struct FILE *fp, struct rr_entry *entry, void *buf, size_t size);

//void output_rr_string(struct FILE *fp, uint8_t const *buf, size_t size);
//void input_rr_string(struct FILE *fp, uint8_t *buf, size_t size);

static inline uint64_t rdtsc(void) {
  uint32_t lo, hi;
  /* We cannot use "=A", since this would use %rax on x86_64 */
  __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
  return (uint64_t)hi << 32 | lo;
}

extern struct FILE *recording_fp, *replaying_fp;
extern struct FILE *drift_fp;
extern char const *recording_file, *replaying_file;
extern unsigned long long stats_rr_log_rw_time_sum;
extern bool rr_log_format_human, log_drift;
extern bool replay_pipe_drain;
extern bool translating;
extern jmp_buf jmp_tb;
extern struct kvm_run *rr_run;
extern unsigned long long stats_io_start_time, stats_io_time_sum;
bool rr_entry_is_timer_interrupt(struct rr_entry const *entry);
/* for imul */
extern uint32_t imul_cc_src, imul_cc_dst, imul_cc_op, rr_eflags;
extern int cpu_number, prev_cpu_number;
#endif
