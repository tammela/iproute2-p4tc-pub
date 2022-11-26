/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _P4TC_COMMON_H_
#define _P4TC_COMMON_H_

#include "list.h"
#include "tc_util.h"

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

void parse_path(char *path, char **p4tcpath, const char *separator);
int get_obj_type(const char *str_obj_type);
struct p4_metat_s *get_meta_byname(const char *pname, const char *name);
struct p4_metat_s *get_meta_byid(const __u32 pipeid, const __u32 id);
void register_kernel_metadata(void);
void unregister_kernel_metadata(void);
void register_new_metadata(struct p4_metat_s *meta);
void unregister_metadata(struct p4_metat_s *meta);
int fill_user_metadata(struct p4_metat_s metadata[]);

#define STR_IS_EMPTY(str) ((str)[0] == '\0')

int concat_cb_name(char *full_name, const char *cbname,
		   const char *objname, size_t sz);
#endif
