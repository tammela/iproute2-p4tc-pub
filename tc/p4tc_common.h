/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _P4TC_COMMON_H_
#define _P4TC_COMMON_H_

#include <stdio.h>
#include <string.h>

#include "list.h"
#include "tc_util.h"
#include "p4_types.h"
#include "p4_tc_json.h"

#include <uapi/linux/p4tc.h>

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
#define PATH_REGNAME_IDX 2

#define PATH_PARSERNAME_IDX 2
#define PATH_HDRNAME_IDX 3
#define PATH_HDRFIELDNAME_IDX 4

#define MAX_PATH_COMPONENTS 5

#define STR_IS_EMPTY(str) ((str)[0] == '\0')

/* PATH SYNTAX: tc p4template objtype/pname/...  */
static inline void parse_path(char *path, char **p4tcpath, const char *separator)
{
	int i = 0;
	char *component;

	component = strtok(path, separator);
	while (component) {
		p4tcpath[i++] = component;
		component = strtok(NULL, separator);
	}
}

static inline int get_obj_type(const char *str_obj_type)
{
       if (!strcmp(str_obj_type, "pipeline"))
               return P4TC_OBJ_PIPELINE;
       else if (!strcmp(str_obj_type, "metadata"))
               return P4TC_OBJ_META;
       else if (!strcmp(str_obj_type, "table"))
               return P4TC_OBJ_TABLE;
       else if (!strcmp(str_obj_type, "hdrfield"))
               return P4TC_OBJ_HDR_FIELD;
       else if (!strcmp(str_obj_type, "action"))
               return P4TC_OBJ_ACT;
       else if (!strcmp(str_obj_type, "register"))
               return P4TC_OBJ_REGISTER;

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

struct p4_metat_s {
        __u32 id;
        int containid;
	__u8 startbit;
	__u8 endbit;
        char name[256];
	__u32 pipeid;
	struct hlist_node hlist;
	char pname[256];
};

struct p4_param_s {
	__u32 id;
	__u32 actid;
	__u32 pipeid;
	char pname[256];
        char name[256];
	int containid;
	__u8 startbit;
	__u8 endbit;
};

struct p4_reg_s {
	char pname[PIPELINENAMSIZ];
	char name[REGISTERNAMSIZ];
	__u32 pipeid;
	__u32 id;
	int containid;
	__u32 startbit;
	__u32 endbit;
};

struct p4_metat_s *get_meta_byname(const char *pname, const char *name);
struct p4_metat_s *get_meta_byid(const __u32 pipeid, const __u32 id);
void register_kernel_metadata(void);
void unregister_kernel_metadata(void);
void register_new_metadata(struct p4_metat_s *meta);
void unregister_metadata(struct p4_metat_s *meta);
int fill_user_metadata(struct p4_metat_s metadata[]);

#define TABLEKEYNAMSIZ TEMPLATENAMSZ

struct parse_state {
	bool has_parsed_keys;
	int num_keys;
	__u8 keyblob[P4TC_MAX_KEYSZ];
	__u8 maskblob[P4TC_MAX_KEYSZ];
};

int parse_new_table_entry(int *argc_p, char ***argv_p, struct nlmsghdr *n,
                         struct parse_state *state, char *p4tcpath[],
                         const char *pname, __u32 *ids, __u32 *offset);

int p4tc_print_permissions(const char *prefix, __u16 *passed_permissions,
			   const char *suffix, FILE *f);
int print_table_entry(struct nlmsghdr *n, struct rtattr *arg, FILE *f,
		      const char *prefix, struct table *table, __u32 tbl_id);

#endif
