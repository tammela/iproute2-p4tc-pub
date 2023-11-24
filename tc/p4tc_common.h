/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _P4TC_COMMON_H_
#define _P4TC_COMMON_H_

#include <stdio.h>
#include <string.h>

#include "list.h"
#include "tc_util.h"
#include "p4_types.h"
#include "p4tc_json.h"

#include <uapi/linux/p4tc.h>
#include <linux/rtnetlink.h>

#ifndef INTROSPECTION_PATH
#define INTROSPECTION_PATH "/etc/iproute2/introspection"
#endif

#define TMPL_ARRAY_START_IDX 1
#define PATH_OBJ_IDX 0
#define PATH_PNAME_IDX 1
#define PATH_CBNAME_IDX 2
#define PATH_MNAME_IDX 3
#define PATH_TBLNAME_IDX 3
#define PATH_ANAME_IDX 3
#define PATH_PIPEANAME_IDX 3
#define PATH_TBLANAME_IDX 4
#define PATH_REGNAME_IDX 2
#define PATH_EXTNAME_IDX 2
#define PATH_EXTINSTNAME_IDX 3
#define PATH_RUNTIME_EXTNAME_IDX 2
#define PATH_RUNTIME_EXTINSTNAME_IDX 3
#define PATH_TABLE_OBJ_IDX 1
#define PATH_TABLE_PNAME_IDX 0
#define PATH_RUNTIME_EXT_PNAME_IDX PATH_TABLE_PNAME_IDX

#define MAX_PATH_COMPONENTS 6

#define STR_IS_EMPTY(str) ((str)[0] == '\0')

/* PATH SYNTAX: tc p4template objtype/pname/...  */
static inline int parse_path(char *path, char **p4tcpath, const char *separator)
{
	int i = 0;
	char *component;

	component = strtok(path, separator);
	while (component) {
		if (i == MAX_PATH_COMPONENTS) {
			fprintf(stderr, "Max path components exceeded\n");
			return -1;
		}

		p4tcpath[i++] = component;
		component = strtok(NULL, separator);
	}

	return i;
}

static inline int get_obj_type(const char *str_obj_type)
{
       if (!strcmp(str_obj_type, "pipeline"))
               return P4TC_OBJ_PIPELINE;
       else if (!strcmp(str_obj_type, "table"))
               return P4TC_OBJ_TABLE;
       else if (!strcmp(str_obj_type, "action"))
               return P4TC_OBJ_ACT;
       else if (!strcmp(str_obj_type, "extern"))
               return P4TC_OBJ_EXT;
       else if (!strcmp(str_obj_type, "extern_inst"))
               return P4TC_OBJ_EXT_INST;

       return -1;
}

static inline int get_obj_runtime_type(const char *str_obj_type)
{
       if (!strcmp(str_obj_type, "table"))
               return P4TC_OBJ_RUNTIME_TABLE;
       else if (!strcmp(str_obj_type, "extern"))
               return P4TC_OBJ_RUNTIME_EXTERN;

       return -1;
}

static inline int concat_cb_name(char *full_name, const char *cbname,
			   const char *objname, size_t sz)
{
	return snprintf(full_name, sz, "%s/%s", cbname, objname) >= sz ? -1 : 0;
}

static inline int try_strncpy(char *dest, const char *src, size_t max_len)
{
	if (strnlen(src, max_len) == max_len)
		return -1;

	strcpy(dest, src);

	return 0;
}

static inline bool p4tc_is_tmpl_cmd(__u16 nlmsg_type) {
	return (nlmsg_type == RTM_CREATEP4TEMPLATE ||
		nlmsg_type == RTM_UPDATEP4TEMPLATE ||
		nlmsg_type == RTM_GETP4TEMPLATE ||
		nlmsg_type == RTM_DELP4TEMPLATE);
}

static inline bool p4tc_is_runtime_cmd(__u16 nlmsg_type) {
	return (nlmsg_type == RTM_P4TC_CREATE ||
		nlmsg_type == RTM_P4TC_UPDATE  ||
		nlmsg_type == RTM_P4TC_GET ||
		nlmsg_type == RTM_P4TC_DEL);
}

struct parse_state {
	bool has_parsed_keys;
	int num_keys;
	__u8 keyblob[P4TC_MAX_KEYSZ];
	__u8 maskblob[P4TC_MAX_KEYSZ];
};

int p4tc_pipeline_get_id(const char *pname, __u32 *pipeid);

#ifdef P4TC
int do_p4tmpl(int argc, char **argv);
int print_p4tmpl(struct nlmsghdr *n, void *arg);
#else
#define P4TC_LIBBPF_MIN_VERSION "0.0.8"

static inline int do_p4tmpl(int argc, char **argv) {
		fprintf(stderr, "Must compile with libbpf >= %s to use P4TC\n",
			P4TC_LIBBPF_MIN_VERSION);
	return -1;
}

static inline int print_p4tmpl(struct nlmsghdr *n, void *arg) {
	fprintf(stderr, "Must compile with libbpf >= %s to use P4TC\n",
		P4TC_LIBBPF_MIN_VERSION);
	return -1;
}
#endif

int print_dyna_parms(struct action_util *au, struct rtattr *arg, FILE *f);

int parse_dyna(int *argc_p, char ***argv_p, bool in_act, char *actname,
	       struct nlmsghdr *n);
int parse_dyna_tbl_act(int *argc_p, char ***argv_p, char **actname_p,
		       const char *tblname, const bool introspect_global,
		       struct nlmsghdr *n, bool params_only);
int print_dyna_parms(struct action_util *au, struct rtattr *arg, FILE *f);
struct p4tc_json_actions_list *
introspect_action_byname(struct p4tc_json_pipeline **pipe,
			 const char **p4tcpath);

struct p4tc_act_param {
	char name[P4TC_ACT_PARAM_NAMSIZ];
	struct p4_type_s *type;
	__u32 id;
	__u32 bitsz;
	__u8 flags;
};

int dyna_add_param(struct p4tc_act_param *param, void *value, bool in_act,
		   struct nlmsghdr *n, bool convert_value);

int
p4tc_act_param_build(struct p4tc_json_actions_list *act,
		     struct p4tc_act_param *param, const char *param_name,
		     bool fail_introspection);

#ifdef P4TC
int do_p4_runtime(int argc, char **argv);
int print_p4ctrl(struct nlmsghdr *n, void *arg);
#else
static inline int do_p4_runtime(int argc, char **argv)
{
	fprintf(stderr, "Must compile with libbpf >= %s to use P4TC\n",
		P4TC_LIBBPF_MIN_VERSION);
	return -1;
}

static inline int print_p4ctrl(struct nlmsghdr *n, void *arg)
{
	fprintf(stderr, "Must compile with libbpf >= %s to use P4TC\n",
		P4TC_LIBBPF_MIN_VERSION);
	return -1;
}
#endif
int parse_new_table_entry(int *argc_p, char ***argv_p, struct nlmsghdr *n,
                         struct parse_state *state, char *p4tcpath[],
                         const char *pname, __u32 *ids, __u32 *offset);
int print_table(struct nlmsghdr *n, void *arg);

int parse_table_entry(int cmd, int *argc_p, char ***argv_p,
                     char *p4tcpath[], struct nlmsghdr *n,
                     unsigned int *flags);
int parse_table_entry_help(int cmd, char **p4tcpath);
int parse_table_default_action(int *argc_p, char ***argv_p,
			       struct nlmsghdr *n, __u32 attr_id);
struct p4tc_json_key_fields_list *
introspect_key_field_byname(struct p4tc_json_pipeline **p,
			    struct p4tc_json_table **t, const char *pname,
			    const char **p4tcpath, const char *keyname);
int parse_p4tc_extern(struct nlmsghdr *n, int cmd, unsigned int *flags,
		       int *argc_p, char ***argv_p, const char **p4tcpath);
int parse_extern_help(int cmd, char **p4tcpath);
int p4tc_extern_parse_inst_param(int *argc_p, char ***argv_p, bool in_act,
				 int *parms_count,
				 struct p4tc_json_extern_insts_list *inst,
				 struct nlmsghdr *n);

int p4tc_print_permissions(const char *prefix, __u16 *passed_permissions,
			   const char *suffix, FILE *f);
int print_table_entry(struct nlmsghdr *n, struct rtattr *arg, FILE *f,
		      const char *prefix, struct p4tc_json_table *table,
		      __u32 tbl_id);
int p4tc_extern_inst_print_params(struct rtattr *arg, FILE *f);
int print_extern(struct nlmsghdr *n, void *arg);
int p4tc_print_one_extern(FILE *f, struct rtattr *arg, bool bind);

#endif
