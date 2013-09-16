#ifndef QEMU_CPUS_H
#define QEMU_CPUS_H

/* cpus.c */
int qemu_init_main_loop(void);
void qemu_main_loop_start(void);
void resume_all_vcpus(void);
void pause_all_vcpus(void);
void finish_qemu_rr(void);
int qemu_rr_entry_valid(void);
void do_flush_all(void);
/* vl.c */
extern int smp_cores;
extern int smp_threads;
extern int debug_requested;
extern int vmstop_requested;
void vm_state_notify(int running, int reason);
void save_load_state(char*);
bool cpu_exec_all(void);
void set_numa_modes(void);
void set_cpu_log(const char *optarg);
void list_cpus(FILE *f, int (*cpu_fprintf)(FILE *f, const char *fmt, ...),
               const char *optarg);
void init_counter(void);
void vcpus_get_eips(uint64_t *eips, size_t eips_size);
void vcpus_get_ecxs(uint64_t *ecxs, size_t ecxs_size);
void vcpus_get_n_branches(uint64_t *n_branches, size_t n_branches_size);
void vcpus_set_n_branches(uint64_t *n_branches, size_t n_branches_size);
int vcpus_read_state_from_pipe(int fd);
void vcpus_write_state_from_pipe(int fd);
void print_state(void);
#endif
