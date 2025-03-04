/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TC_UTIL_H_
#define _TC_UTIL_H_ 1

#define MAX_MSG 16384
#include <limits.h>
#include <linux/if.h>
#include <stdbool.h>

#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/gen_stats.h>
#include <linux/p4tc.h>

#include "tc_core.h"
#include "json_print.h"

/* This is the deprecated multiqueue interface */
#ifndef TCA_PRIO_MAX
enum
{
	TCA_PRIO_UNSPEC,
	TCA_PRIO_MQ,
	__TCA_PRIO_MAX
};

#define TCA_PRIO_MAX    (__TCA_PRIO_MAX - 1)
#endif

#define FILTER_NAMESZ	16

struct qdisc_util {
	struct qdisc_util *next;
	const char *id;
	int (*parse_qopt)(const struct qdisc_util *qu, int argc,
			  char **argv, struct nlmsghdr *n, const char *dev);
	int (*print_qopt)(const struct qdisc_util *qu,
			  FILE *f, struct rtattr *opt);
	int (*print_xstats)(const struct qdisc_util *qu,
			    FILE *f, struct rtattr *xstats);

	int (*parse_copt)(const struct qdisc_util *qu, int argc,
			  char **argv, struct nlmsghdr *n, const char *dev);
	int (*print_copt)(const struct qdisc_util *qu, FILE *f, struct rtattr *opt);
	int (*has_block)(const struct qdisc_util *qu, struct rtattr *opt,
			 __u32 block_idx, bool *p_has);
};

struct tc_filter_fields {
	char *handle;
	__u32 chain;
	__u32 classid;
	__be16 proto;
	__u16 prio;
};

extern __u16 f_proto;
struct filter_util {
	struct filter_util *next;
	char id[FILTER_NAMESZ];
	int (*parse_fopt)(const struct filter_util *qu,
			  struct tc_filter_fields *filter_fields,
			  int argc, char **argv, struct nlmsghdr *n);
	int (*print_fopt)(const struct filter_util *qu,
			  FILE *f, struct rtattr *opt, __u32 fhandle);
};

struct action_util {
	struct action_util *next;
	char id[ACTNAMSIZ];
	__u32 aid;
	int (*parse_aopt)(const struct action_util *a, int *argc,
			  char ***argv, int code, struct nlmsghdr *n);
	int (*print_aopt)(const struct action_util *au, FILE *f, struct rtattr *opt);
	int (*print_xstats)(const struct action_util *au,
			    FILE *f, struct rtattr *xstats);
};

struct exec_util {
	struct exec_util *next;
	char id[FILTER_NAMESZ];
	int (*parse_eopt)(const struct exec_util *eu, int argc, char **argv);
};

const char *get_tc_lib(void);

struct action_util *get_action_kind(const char *str);
struct action_util *get_action_byid(__u32 actid);
void discover_actions(void);
void print_known_actions(void);
const struct qdisc_util *get_qdisc_kind(const char *str);
const struct filter_util *get_filter_kind(const char *str);

int get_qdisc_handle(__u32 *h, const char *str);
int get_percent_rate(unsigned int *rate, const char *str, const char *dev);
int get_percent_rate64(__u64 *rate, const char *str, const char *dev);
int get_size_and_cell(unsigned int *size, int *cell_log, char *str);
int get_linklayer(unsigned int *val, const char *arg);

void tc_print_rate(enum output_type t, const char *key, const char *fmt,
		   unsigned long long rate);
void print_devname(enum output_type type, int ifindex);

char *sprint_tc_classid(__u32 h, char *buf);
char *sprint_linklayer(unsigned int linklayer, char *buf);

void print_tcstats_attr(FILE *fp, struct rtattr *tb[],
			const char *prefix, struct rtattr **xstats);
void print_tcstats2_attr(struct rtattr *rta, const char *prefix, struct rtattr **xstats);

int get_tc_classid(__u32 *h, const char *str);
int print_tc_classid(char *buf, int len, __u32 h);
char *sprint_tc_classid(__u32 h, char *buf);

int tc_print_police(struct rtattr *tb);
int parse_percent(double *val, const char *str);
int parse_police(int *argc_p, char ***argv_p, int tca_id, struct nlmsghdr *n);

int parse_action_control(int *argc_p, char ***argv_p,
			 int *result_p, bool allow_num);
void parse_action_control_dflt(int *argc_p, char ***argv_p,
			       int *result_p, bool allow_num,
			       int default_result);
int parse_action_control_slash(int *argc_p, char ***argv_p,
			       int *result1_p, int *result2_p, bool allow_num);
void print_action_control(const char *prefix, int action, const char *suffix);
int police_print_xstats(const struct action_util *a, FILE *f, struct rtattr *tb);
int tc_print_action(FILE *f, const struct rtattr *tb, unsigned short tot_acts);
int parse_action(int *argc_p, char ***argv_p, int tca_id, struct nlmsghdr *n);
int parse_hw_stats(const char *str, struct nlmsghdr *n);
void print_tm(const struct tcf_t *tm);
int prio_print_opt(const struct qdisc_util *qu, FILE *f, struct rtattr *opt);

int cls_names_init(char *path);
void cls_names_uninit(void);

#define CLOCKID_INVALID (-1)
int get_clockid(__s32 *val, const char *arg);
const char *get_clock_name(clockid_t clockid);

int action_a2n(char *arg, int *result, bool allow_num);

bool tc_qdisc_block_exists(__u32 block_index);

void print_masked_u32(const char *name, struct rtattr *attr,
		      struct rtattr *mask_attr, bool newline);
void print_masked_u16(const char *name, struct rtattr *attr,
		      struct rtattr *mask_attr, bool newline);
void print_masked_u8(const char *name, struct rtattr *attr,
		     struct rtattr *mask_attr, bool newline);
void print_masked_be16(const char *name, struct rtattr *attr,
		       struct rtattr *mask_attr, bool newline);

void print_ext_msg(struct rtattr **tb);
#endif
