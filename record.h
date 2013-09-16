#ifndef RECORD_H
#define RECORD_H
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "rr_log_consts.h"

#define MAX_NUM_CPUS 255
//#include "monitor.h"

struct kvm_run;
struct rr_entry;

/*
void do_record_start(Monitor *mon, const QDict *qdict);
void do_record_stop(Monitor *mon, const QDict *qdict);
void do_replay_start(Monitor *mon, const QDict *qdict);
void do_replay_stop(Monitor *mon, const QDict *qdict);
*/

void record_start(char const *filename);
void replay_start(char const *filename);

void replay_stop(void);
void record_stop(void);

void record_snapshot(char const *filename);
void replay_snapshot(char const *filename);

void cope_with_branch_mismatch(struct kvm_run *run, struct rr_entry *entry);

void register_deterministic_func_pointer(void *func);
int mmin_is_deterministic(void *func_pointer);
void do_iomem_log(char const *function, void *func_pointer);

struct VLANClientState;
void rr_register_net_client(struct VLANClientState *nc);
struct VLANClientState *rr_vlan_client_state(void);

struct VLANClientState;
ssize_t e1000_receive(struct VLANClientState *nc, const uint8_t *buf, size_t size);
void do_call_e1000_receive(void);

int rr_event_is_external(unsigned event);
int rr_event_is_external_io(unsigned event);

void dump_stats(int signum);

void rollback(struct kvm_run *run);

struct FILE;
//extern struct FILE *recording_fp, *replaying_fp;

extern void *last_io_function;
extern int snapshot_now;

extern unsigned long long tsc_start;
extern unsigned long long kvm_cpu_exec_time;
//uint64_t rdtsc(void);
void rr_ram_write(unsigned long addr, uint8_t *buf, size_t size);
void replay_till(uint64_t rollback_n_branches, uint32_t rollback_eip, uint32_t rollback_ecx);
void last_n_interrupts_tail(uint64_t *n_branches, uint32_t *eip, uint32_t *ecx);


extern char const *rr_drive_file;
extern char const *record_snapshot_file;
//extern char const *recording_file, *replaying_file;

void replay_begin(void);

void last_n_interrupts_window_push(uint64_t n_branches, uint32_t eip, uint32_t ecx);

void rr_entries_to_buffer(int tag, void *buf, size_t size);
void buffer_to_rr_entries(int tag, const void *buf, size_t size);
void rr_shutdown(void);

/* Changes to these constants should also be reflected in kernel code. */
//#define TIMER_INTR_VECTOR 0xef              //linux with apic
#define TIMER_INTR_VECTOR 0x30              //linux without apic
//#define TIMER_INTR_VECTOR 0x20              //pintos

extern char *start_record;
extern int trying_to_cope_with_branch_mismatch;

extern int record_minimal;

uint64_t hw_replay(uint8_t tag);
void hw_record(uint64_t val, uint8_t tag);
uint8_t rr_inb(struct kvm_run *run, uint16_t port);
uint16_t rr_inw(struct kvm_run *run, uint16_t port);
uint32_t rr_inl(struct kvm_run *run, uint16_t port);


#endif
