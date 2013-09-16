#include "record.h"
#include <stdio.h>
#include <execinfo.h>
#include <stdio.h>
#include <mydebug.h>
#include <execinfo.h>
#include "rr_log.h"
#include "sysemu.h"
#include "block.h"
#include "block_int.h"
#include "hw/hw.h"
#include "cpus.h"
#include <linux/kvm.h>
#include "kvm.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include "monitor.h"
#include "net.h"

#define DEFAULT_LOGFILE "record.log"
char *start_record = NULL;
Monitor *default_monitor = NULL;
void *last_io_function = NULL;
int snapshot_now = 0;

unsigned long long tsc_start;
unsigned long long kvm_cpu_exec_time = 0;

char const *rr_drive_file = NULL;

int record_minimal = 1;


int myfprintf(FILE *stream, const char *format, ...);
int myfscanf(FILE *stream, const char *format, ...);
void do_replay_start(Monitor *mon, const QDict *qdict);
void do_replay_stop(Monitor *mon, const QDict *qdict);

static int _qemu_savevm_state(char const *filename)
{
  int ret;
  QEMUFile *f;

  f = qemu_fopen(filename, "wb");
  ASSERT(f);
  ret = qemu_savevm_state(default_monitor, f);
  qemu_fclose(f);
  return ret;
}

static int _qemu_loadvm_state(char const *filename)
{
  int ret;
  QEMUFile *f;

  f = qemu_fopen(filename, "rb");
  ASSERT(f);
  ret = qemu_loadvm_state(f);
  qemu_fclose(f);
  return ret;
}

static int _bdrv_snapshot_goto(BlockDriverState *bs,
    QEMUSnapshotInfo *sn_info)
{
  return bdrv_snapshot_goto(bs, sn_info->id_str);
}

#define do_rr_snapshot(rr, prefix) do {                                     \
  QEMUSnapshotInfo sn1, *sn = &sn1;                                         \
  FILE *rr_fp = (FILE *)rr##ing_fp;                                         \
  char const *rr_string = #rr;                                              \
  char const *rr_file = rr##ing_file;                                       \
  int (*qemu_loadsavevm_state)(char const *filename);                       \
  int (*fprintf_fscanf)(FILE *fp, char const *format, ...);                 \
  int (*bdrv_snapshot_creategoto)(BlockDriverState *, QEMUSnapshotInfo *);  \
  BlockDriverState *bs1;                                                    \
  unsigned long long n_branches[MAX_NUM_CPUS], n_branches_log[MAX_NUM_CPUS];\
  unsigned long long eips[MAX_NUM_CPUS], eips_log[MAX_NUM_CPUS];            \
  unsigned long long ecxs[MAX_NUM_CPUS], ecxs_log[MAX_NUM_CPUS];            \
  struct timeval tv;                                                        \
  int ret = 0;                                                              \
									    \
  if (!strcmp(rr_string, "record")) {                                       \
    bdrv_snapshot_creategoto = &bdrv_snapshot_create;                       \
    qemu_loadsavevm_state = &_qemu_savevm_state;                            \
    fprintf_fscanf = &myfprintf;                                            \
  } else if (!strcmp(rr_string, "replay")) {                                \
    bdrv_snapshot_creategoto = &_bdrv_snapshot_goto;                        \
    qemu_loadsavevm_state = &_qemu_loadvm_state;                            \
    fprintf_fscanf = &myfscanf;                                             \
  } else ASSERT(0);                                                         \
                                                                            \
  vcpus_get_n_branches((uint64_t *)n_branches, MAX_NUM_CPUS);               \
  vcpus_get_eips((uint64_t *)eips, MAX_NUM_CPUS);                           \
  vcpus_get_ecxs((uint64_t *)ecxs, MAX_NUM_CPUS);                           \
                                                                            \
  memcpy(n_branches_log, n_branches, sizeof n_branches);                    \
  memcpy(eips_log, eips, sizeof eips);                                      \
  memcpy(ecxs_log, ecxs, sizeof ecxs);                                      \
                                                                            \
  if (!rr_log_format_human && !strcmp(rr_string, "replay")) {               \
    input_rr_record(replaying_fp, &replay_entry,replay_buf,replay_buf_size);\
  }                                                                         \
  char snapshot_filename[strlen(rr_file) + 64];                             \
  snprintf(snapshot_filename, sizeof snapshot_filename,                     \
      "%s.snap.%d", rr_file, snapshot_num);                                 \
  (*fprintf_fscanf)(rr_fp, "MS:   %016llx", prefix n_branches_log[0]);      \
  (*fprintf_fscanf)(rr_fp, " %08llx", prefix eips_log[0]);                  \
  (*fprintf_fscanf)(rr_fp, " %08llx", prefix ecxs_log[0]);                  \
  if (!strcmp(rr_string, "replay")) {                                       \
    n_branches[0] = n_branches_log[0];                                      \
  }                                                                         \
  if (!snapshot_exists) {                                                   \
    (*fprintf_fscanf)(rr_fp, ": %s", snapshot_filename);                    \
    vm_stop(0);                                                             \
    qemu_aio_flush();                                                       \
    ret = (*qemu_loadsavevm_state)(snapshot_filename);                      \
    if (qemu_loadsavevm_state == &qemu_comparevm_state) {                   \
      if (ret == 0) {                                                       \
        printf("MS check succeeded at %llx\n", n_branches[0]);              \
      } else {                                                              \
        printf("MS check failed at %llx\n", n_branches[0]);                 \
        exit(1);                                                            \
      }                                                                     \
    } else {                                                                \
      vcpus_set_n_branches((uint64_t *)n_branches, MAX_NUM_CPUS);           \
    }                                                                       \
    if (ret < 0) {                                                          \
      printf("Error %d while %s VM\n", ret, rr_string);                     \
      mybacktrace();                                                        \
      exit(1);                                                              \
    }                                                                       \
    if (!strcmp(rr_string, "record")) {                                     \
      memset(sn, 0, sizeof(*sn));                                           \
      gettimeofday(&tv, NULL);                                              \
      sn->date_sec = tv.tv_sec;                                             \
      sn->date_nsec = tv.tv_usec * 1000;                                    \
      sn->vm_clock_nsec = qemu_get_clock(vm_clock);                         \
      sn->vm_state_size = 0;                                                \
    }                                                                       \
    if (   (!strcmp(rr_string, "record") && !record_output_bdrv)            \
        || (!strcmp(rr_string, "replay") && !replay_output_bdrv)) {         \
      bs1 = NULL;                                                           \
      while ((bs1 = bdrv_next(bs1))) {                                      \
        if (bdrv_can_snapshot(bs1)) {                                       \
          char filename[1024];                                              \
          if (!strcmp(rr_string, "replay")) {                               \
            BlockDriver *drv;                                               \
            int n;                                                          \
            n = myfscanf(rr_fp, " %[^:]:%s", filename,                      \
                sn->id_str);                                                \
            ASSERT(n >= 2);                                                 \
            drv = bs1->drv;                                                 \
            bdrv_close(bs1);                                                \
            if (bdrv_open(bs1, filename, BDRV_O_RDWR, drv) < 0) {           \
              printf("bdrv_open(%s) failed.\n", filename);                  \
            }                                                               \
          }                                                                 \
          ret = (*bdrv_snapshot_creategoto)(bs1, sn);                       \
          if (!strcmp(rr_string, "record")) {                               \
              myfprintf(rr_fp, " %s:%s", bs1->filename, sn->id_str);        \
          }                                                                 \
          if (ret < 0) {                                                    \
            printf("Error while %sing snapshot on "                         \
                "'%s'\n", rr_string, bdrv_get_device_name(bs1));            \
            retval = -1;                                                    \
            mybacktrace();                                                  \
          }                                                                 \
        }                                                                   \
      }                                                                     \
    }                                                                       \
    vm_start();                                                             \
  } else {                                                                  \
    (*fprintf_fscanf)(rr_fp, ": %s", snapshot_exists);                      \
  }                                                                         \
  (*fprintf_fscanf)(rr_fp, "\n");                                           \
} while(0)

void
replay_begin(void)
{
  replay_snapshot(NULL);
}

#define do_rr_start(rr, prefix) do {                                        \
  char const *mode;                                                         \
  char const *rr_string = #rr;                                              \
  if (rr##ing_fp) {                                                         \
    monitor_printf(mon, "%s already in progress.\n", rr_string);            \
    return;                                                                 \
  }                                                                         \
  if (!strcmp(rr_string, "record")) {                                       \
    mode = "w";                                                             \
  } else if (!strcmp(rr_string, "replay")) {                                \
    mode = "r+";                                                            \
  }                                                                         \
  if (!kvm_enabled()) {                                                     \
     do_flush_all();                                                        \
  }                                                                         \
  rr##ing_file = strdup(filename);                                          \
  rr##ing_fp = (struct FILE *)fopen(filename, mode);                        \
  if (!rr##ing_fp) {                                                        \
    printf("Failed to open %s file %s in '%s' mode: %s. Exiting.\n",        \
        rr_string, filename, mode, strerror(errno));                        \
    exit(1);                                                                \
  }                                                                         \
  monitor_printf(mon, "Starting %s to %s\n", rr_string, filename);          \
  rr##_snapshot(NULL);                                                      \
  if (rr_log_format_human) {                                                \
    NOT_REACHED();                                                          \
  }                                                                         \
} while (0)

static int snapshot_num = 0;

void
record_snapshot(char const *snapshot_exists)
{
  int retval = 0;
  ASSERT(recording_fp);
  do_rr_snapshot(record, );
  if (retval < 0) {
    exit(1);
  }
  snapshot_num++;
}

void
replay_snapshot(char const *snapshot_exists)
{
  int retval = 0;
  ASSERT(snapshot_exists == NULL);
  ASSERT(replaying_fp);
  do_rr_snapshot(replay, &);
  if (retval < 0) {
    exit(1);
  }
}

static bool
rr_supported(Monitor *mon)
{
  if (smp_cpus > 1) {
    monitor_printf(mon, "R/R not supported for SMPs (num_cpus=%d)\n", smp_cpus);
    return false;
  }
  return true;
}

static void record_start_on_mon(Monitor *mon, char const *filename)
{
  if (!kvm_enabled()) {
    init_counter();
  }
  do_rr_start(record, );
  if (kvm_enabled()) {
    asynchronous_net_deliveries = true;
  }
}

void record_start(char const *filename)
{
  record_start_on_mon(default_monitor, filename);
}

static void replay_start_on_mon(Monitor *mon, char const *filename)
{
  do_rr_start(replay, &);
}

void replay_start(char const *filename)
{
  replay_start_on_mon(default_monitor, filename);
}

void do_replay_start(Monitor *mon, const QDict *qdict)
{
  char const *filename;
  if (!rr_supported(mon)) {
    return;
  }
  filename = qdict_get_try_str(qdict, "filename");
  if (!filename) {
    filename = DEFAULT_LOGFILE;
  }
  replay_start_on_mon(mon, filename);
}

void replay_stop(void)
{
  if (!kvm_enabled()) {
    finish_qemu_rr();
  }

  if (replaying_file) {
    free((void *)replaying_file);
    replaying_file = NULL;
  }
  if (replaying_fp) {
    fclose((FILE *)replaying_fp);
  }
  replaying_fp = NULL;
}

void record_stop(void)
{
  if (!kvm_enabled()) {
    finish_qemu_rr();
  }
  if (recording_file) {
    free((void *)recording_file);
    recording_file = NULL;
  }
  if (recording_fp) {
    fclose((FILE *)recording_fp);
  }
  recording_fp = NULL;
}

void do_replay_stop(Monitor *mon, const QDict *qdict)
{
  if (!rr_supported(mon)) {
    return;
  }
  if (!replaying_fp) {
    monitor_printf(mon, "No replaying session to stop.\n");
    return;
  }
  monitor_printf(mon, "Stopping replay.\n");
  replay_stop();
}

void
cope_with_branch_mismatch(struct kvm_run *run, struct rr_entry *entry)
{
	ASSERT(0);
}

#define MAX_DETERMINISTIC_FUNC_POINTERS 1024
static void *deterministic_func_pointers[MAX_DETERMINISTIC_FUNC_POINTERS];
static int num_deterministic_func_pointers = 0;

void register_deterministic_func_pointer(void *func)
{
  ASSERT(num_deterministic_func_pointers < MAX_DETERMINISTIC_FUNC_POINTERS);
  deterministic_func_pointers[num_deterministic_func_pointers++] = func;
}

int
mmin_is_deterministic(void *func_pointer)
{
  int i;

  for (i = 0; i < sizeof deterministic_func_pointers/sizeof deterministic_func_pointers[0]; i++) {
    if (func_pointer == deterministic_func_pointers[i]) {
      return 1;
    }
  }
  return 0;
}

void
do_iomem_log(char const *function, void *func_pointer)
{
  if (!mmin_is_deterministic(func_pointer)) {
    //printf("%s(): io_mem_read = %p\n", __func__, func_pointer);
  }
  last_io_function = func_pointer;
}



static struct VLANClientState *rr_nc = NULL;

void
rr_register_net_client(struct VLANClientState *nc)
{
  if (!rr_nc) {
    rr_nc = nc;
  } else {
    printf("%s(): Error: re-registering nc.\n", __func__);
    mybacktrace();
    exit(1);
  }
}

struct VLANClientState *
rr_vlan_client_state(void)
{
  return rr_nc;
}

int
rr_event_is_external_io(unsigned event)
{
  switch (event) {
    /*case RR_ENTRY_TYPE_NET:
      return 1;*/
    default:
      return 0;
  }
}

int
rr_event_is_external(unsigned event)
{
  switch (event) {
    case RR_ENTRY_TYPE_INTR:
    case RR_ENTRY_TYPE_MS:
    case RR_ENTRY_TYPE_EOMR:
    case RR_ENTRY_TYPE_CPU_SWITCH:
      return 1;
    default:
      return rr_event_is_external_io(event);
  }
}

void 
do_call_e1000_receive(void)
{
  e1000_receive(rr_nc, NULL, 0);
}

void
rr_shutdown(void)
{
  if (recording_fp) {
    struct rr_entry entry;
    uint64_t eips[MAX_NUM_CPUS], ecxs[MAX_NUM_CPUS], n_branches[MAX_NUM_CPUS];
    vcpus_get_eips(eips, MAX_NUM_CPUS);
    vcpus_get_eips(ecxs, MAX_NUM_CPUS);
    vcpus_get_n_branches(n_branches, MAX_NUM_CPUS);
    entry.type = RR_ENTRY_TYPE_SHUTDOWN;
    entry.n_branches = n_branches[cpu_number] ;
    entry.eip = eips[cpu_number] ;
    entry.ecx = ecxs[cpu_number] ;
    entry.ebufsize = 0;
    output_rr_record(recording_fp, &entry, NULL);
  }
}

void
hw_record (uint64_t val, uint8_t tag)
{
  struct rr_entry entry;
  uint64_t eips[MAX_NUM_CPUS];
  uint64_t ecxs[MAX_NUM_CPUS];
  uint64_t n_branches[MAX_NUM_CPUS];

  vcpus_get_eips(eips, MAX_NUM_CPUS);
  vcpus_get_ecxs(ecxs, MAX_NUM_CPUS);
  vcpus_get_n_branches(n_branches, MAX_NUM_CPUS);
  ASSERT(recording_fp);

  entry.type = tag;
  entry.n_branches = n_branches[cpu_number];
  entry.eip = eips[cpu_number];
  entry.ecx = ecxs[cpu_number];
  entry.cpu = cpu_number;
  entry.info = val;
  entry.ebufsize = 0;
  output_rr_record(recording_fp, &entry, NULL);
}

uint64_t
hw_replay (uint8_t tag)
{
  uint64_t eips[MAX_NUM_CPUS];
  uint64_t ecxs[MAX_NUM_CPUS];
  uint64_t n_branches[MAX_NUM_CPUS];
  uint64_t val;

  vcpus_get_eips(eips, MAX_NUM_CPUS);
  vcpus_get_ecxs(ecxs, MAX_NUM_CPUS);
  vcpus_get_n_branches(n_branches, MAX_NUM_CPUS);
  ASSERT(replaying_fp);
  val = replay_entry.info;
  ASSERT(replay_entry.type == tag);
  ASSERT(replay_entry.n_branches == n_branches[cpu_number]);
  ASSERT(replay_entry.ecx == ecxs[cpu_number]);
  ASSERT(replay_entry.ebufsize == 0);
  ASSERT(replay_entry.cpu == cpu_number);
  input_rr_record(replaying_fp, &replay_entry, replay_buf, replay_buf_size);
  return val;
}

void
dump_stats(int signum)
{
  if (!kvm_enabled() && recording_fp) {
    record_stop();
  }
  exit(0);
}

#define rr_in(name, type)                                                 \
  type rr_##name(struct kvm_run *run, uint16_t port) {                    \
    uint32_t info, info1;                                                 \
    info = cpu_##name(port);                                              \
    if (replaying_fp) {                                                   \
      info1 = (uint32_t)hw_replay(RR_ENTRY_TYPE_IN);                      \
      if (info != info1) {             \
        printf("port not matched=%04x info=%08x info1=%08x\n", port, info, info1);  \
        /*info = info1;*/ \
      }\
    } else {                                                              \
      if (recording_fp) {                                                 \
        hw_record(info, RR_ENTRY_TYPE_IN);                                \
      }                                                                   \
    }                                                                     \
    return info;                                                          \
  }

rr_in(inb, uint8_t);
rr_in(inw, uint16_t);
rr_in(inl, uint32_t);
