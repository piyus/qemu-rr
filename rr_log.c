#include "rr_log.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <osdep.h>
#include "qemu-common.h"
#include <mydebug.h>
#include <linux/kvm.h>
#include "record.h"

int myfprintf(FILE *stream, const char *format, ...);
int myfscanf(FILE *stream, const char *format, ...);

unsigned long long stats_io_start_time, stats_io_time_sum;
bool record_output_bdrv = false;
bool replay_output_bdrv = false;
struct kvm_run *rr_run = NULL;
bool asynchronous_net_deliveries = false;
int microreplay_n_timer_interrupts = 0;
bool microreplay_network_send_delay = false;
struct rr_entry replay_entry;
uint8_t replay_buf[MAX_RR_BUF_SIZE];
size_t replay_buf_size = MAX_RR_BUF_SIZE;

char const *recording_file = NULL, *replaying_file = NULL;
struct FILE *recording_fp = NULL, *replaying_fp = NULL;
struct FILE *drift_fp = NULL;
unsigned long long stats_rr_log_rw_time_sum;

bool replay_pipe_drain = false;

bool rr_log_format_human = false;
bool log_drift = false;
bool translating =false;
jmp_buf jmp_tb;
int cpu_number, prev_cpu_number = 0;
uint64_t mismatch_point;

/* for imul */
uint32_t imul_cc_src, imul_cc_dst, imul_cc_op, rr_eflags;

int
myfprintf(FILE  *stream, const char *format, ...)
{
  va_list args;
  int n;

  if (!rr_log_format_human) {
    struct rr_entry entry;
    static char buf[4096];
    size_t len;

    entry.type = RR_ENTRY_TYPE_STRING_BEGIN;
    va_start(args, format);
    n = vsnprintf(buf, sizeof buf, format, args);
    va_end(args);
    len = strlen(buf) + 1;
    ASSERT(len <= sizeof buf);
    //entry.ecx = len;
    entry.ebufsize = len;
    output_rr_record((struct FILE *)stream, &entry, buf);
    //output_rr_string((struct FILE *)stream, (uint8_t *)buf, len);
  } else {
    va_start(args, format);
    n = vfprintf(stream, format, args);
    va_end(args);
  }
  return n;
}

int
myfscanf(FILE  *stream, const char *format, ...)
{
  va_list args;
  int n;

  ASSERT(stream == (FILE *)replaying_fp);
  if (!rr_log_format_human) {

    ASSERT(replay_entry.type == RR_ENTRY_TYPE_STRING_BEGIN);

    va_start(args, format);
    n = vsscanf((char *)replay_buf, format, args);
    va_end(args);

    input_rr_record((struct FILE *)stream, &replay_entry, replay_buf, replay_buf_size);
  } else {
    va_start(args, format);
    n = vfscanf((FILE *)stream, format, args);
    va_end(args);
  }
  return n;
}

#define io_kvm_record(entry, ifp, func, prefix) do {                         \
  int k;                                                                  \
  FILE *fp = (FILE *)ifp;                                                    \
  if ((void *)func == (void *)myfscanf) {                                    \
    entry->type = replay_get_next_entry_type((struct FILE  *)fp);            \
  } else {                                                                   \
    record_put_entry_type((struct FILE *)fp, entry->type);                   \
  }                                                                          \
  switch(entry->type) {                                                      \
    case RR_ENTRY_TYPE_INTR:                                                 \
      k = func(fp, " %016llx %08x %08x: %02llx\n%n",                         \
          prefix entry->n_branches, prefix entry->eip, prefix entry->ecx,    \
          prefix entry->info, &nchars);                                      \
      break;                                                                 \
    case RR_ENTRY_TYPE_IN:                                                   \
      k = func(fp, " %016llx %08x %08x: %08llx: %04hx %02hhx\n%n",           \
          prefix entry->n_branches, prefix entry->eip, prefix entry->ecx,    \
          prefix entry->info, prefix entry->port,                            \
          prefix entry->size, &nchars);                                      \
      break;                                                                 \
    case RR_ENTRY_TYPE_CHECK:                                                \
      k = func(fp, " %016llx %08x %08x\n%n",                                 \
          prefix entry->n_branches, prefix entry->eip, prefix entry->ecx,    \
          &nchars);                                                          \
      break;                                                                 \
    case RR_ENTRY_TYPE_KBD:                                                  \
      k = func(fp, " %016llx %08x %08x: %08llx\n%n",                         \
          prefix entry->n_branches, prefix entry->eip, prefix entry->ecx,    \
          prefix entry->info, &nchars);                                      \
      break;                                                                 \
    case RR_ENTRY_TYPE_NET:                                                  \
    case RR_ENTRY_TYPE_MMIO_IN: \
    case RR_ENTRY_TYPE_MEM:                                                  \
      NOT_REACHED(); \
      /* k = func(fp, " %016llx %08x %08x: %08llx %n",                          \
          prefix entry->n_branches, prefix entry->eip, prefix entry->ecx,    \
          prefix entry->info, &nchars);                                      \
      for (i = 0; i < MIN(entry->info, 8); i++) {                            \
        k = func(fp, " %hhx%n", prefix entry->data[i], &nchars);             \
      }                                                                      \
      k = func(fp, "\n%n", &nchars);                                         \
      */ \
      break;                                                                 \
    case RR_ENTRY_TYPE_APIC:                                                 \
    case RR_ENTRY_TYPE_PM:                                                   \
    case RR_ENTRY_TYPE_PIT:                                                  \
    case RR_ENTRY_TYPE_SER:                                                  \
    case RR_ENTRY_TYPE_EOMR:                                                 \
    case RR_ENTRY_TYPE_HYP:                                                  \
    case RR_ENTRY_TYPE_HPET:                                                 \
    case RR_ENTRY_TYPE_CMOS:                                                 \
    case RR_ENTRY_TYPE_SPK:                                                  \
    case RR_ENTRY_TYPE_RDPMC:                                                \
    case RR_ENTRY_TYPE_RDTSC:                                                \
    case RR_ENTRY_TYPE_DISK_READ:                                            \
    case RR_ENTRY_TYPE_DISK_WRITE:                                           \
    case RR_ENTRY_TYPE_SHM_NETWORK:                                          \
      k = func(fp, " %016llx %08x %08x: %016llx\n%n",                        \
          prefix entry->n_branches, prefix entry->eip, prefix entry->ecx,    \
          prefix entry->info, &nchars);                                      \
      break;                                                                 \
    case RR_ENTRY_TYPE_MICROREPLAY_DUMP:                                     \
    case RR_ENTRY_TYPE_SHUTDOWN:                                             \
      k = func(fp, " %016llx %08x %08x:",                                    \
          prefix entry->n_branches, prefix entry->eip, prefix entry->ecx);   \
      /*if ((void *)func == (void *)myfprintf) {                               \
        myfprintf(fp, " \n");                                                \
      } else {                                                               \
        char buf[3];                                                         \
        int ret; \
        ret = myfread(buf, 1, 2, fp);                                        \
        ASSERT(ret == 2); \
      }*/                                                                    \
      break;                                                                 \
    /*
    case RR_ENTRY_TYPE_DBG:                                                \
      ASSERT((void *)func == (void *)myfprintf);                             \
       k = myfprintf(fp, " %016llx %08x %08x: %016llx %08x %08x %02hhx " \
       "%lx (%lx) %lx (%lx) %llx %llx\n%n",                               \
       entry->n_branches, entry->eip, entry->ecx,                         \
       entry->info, *((uint32_t *)entry->data),                           \
     *((uint32_t *)(((uint8_t *)entry->data + 4))), entry->size,        \
     (long)entry->vector1, (long)entry->dbg1, (long)entry->vector2,     \
     (long)entry->dbg2, (long long)entry->start_brcount,                \
     (long long)entry->stop_brcount, &nchars);                          \
      break;                                                                 \
      */ \
    default:                                                                 \
      break;                                                                 \
  }                                                                          \
} while (0)


static void
log_rr_entry(struct rr_entry *entry)
{
#if 0
  printf("\n<----------------------------------------->\n");
  printf("ENTRY_N_BRANCHES=%llx\n", entry->n_branches);
  printf("ENTRY_ECX=%llx\n", entry->ecx);
  printf("ENTRY_EIP=%llx\n",entry->eip);
  printf("ENTRY_INFO=%llx\n",entry->info);
  printf("ENTRY_TYPE=%x\n",entry->type);
  printf("ENTRY_CPU=%x\n", entry->cpu);
#endif
}

void
output_rr_record(struct FILE *fp, struct rr_entry *entry, const void *buf)
{
  bool was_inside_stats_io = false;
  uint64_t stop_time;
  unsigned long long cur_tsc;
	int ret;

  if (rr_log_format_human) {
    NOT_REACHED();
    return;
  }

  ASSERT(entry->ebufsize == 0 || buf);
  ASSERT(entry->ebufsize <= replay_buf_size);

  cur_tsc = rdtsc();
  if (stats_io_start_time) {
    was_inside_stats_io = true;
    stats_io_time_sum += cur_tsc - stats_io_start_time;
    stats_io_start_time = 0;
  }
  ret = fwrite(entry, sizeof *entry, 1, (FILE *)fp);
  ASSERT(ret == 1);
  if (entry->ebufsize) {
    ret = fwrite(buf, 1, entry->ebufsize, (FILE *)fp);
    ASSERT(ret == entry->ebufsize);
  }
  stop_time = rdtsc();
  if (was_inside_stats_io) {
    stats_io_start_time = stop_time;
  }
  stats_rr_log_rw_time_sum += stop_time - cur_tsc;
}

void
input_rr_record(struct FILE *fp, struct rr_entry *entry, void *buf, size_t size)
{
  bool was_inside_stats_io = false;
  uint64_t stop_time;
  size_t ret;
  unsigned long long cur_tsc;

  if (rr_log_format_human) {
    NOT_REACHED();
    return;
  }

  ASSERT(!replay_pipe_drain);

  cur_tsc = rdtsc();
  if (stats_io_start_time) {
    was_inside_stats_io = true;
    stats_io_time_sum += cur_tsc - stats_io_start_time;
    stats_io_start_time = 0;
  }
  ret = fread(entry, sizeof *entry, 1, (FILE *)fp);
  if (ret != 1) {
    ASSERT(feof((FILE *)fp));
    entry->type = RR_ENTRY_TYPE_INVALID;
    return;
  }
  ASSERT(entry->ebufsize <= size);
  if (entry->ebufsize) {
    ret = fread(buf, 1, entry->ebufsize, (FILE *)fp);
    ASSERT(ret == entry->ebufsize);
  }
  stop_time = rdtsc();
  if (was_inside_stats_io) {
    stats_io_start_time = stop_time;
  }
  stats_rr_log_rw_time_sum += stop_time - cur_tsc;
  return;
}

bool
rr_entry_is_timer_interrupt(struct rr_entry const *entry)
{
  return (entry->type == RR_ENTRY_TYPE_INTR && entry->info == TIMER_INTR_VECTOR);
}


