/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __P4TC_INTROSPECTION_H__
#define __P4TC_INTROSPECTION_H__
#include <linux/pkt_cls.h>
#include <linux/gen_stats.h>
#include <linux/p4tc.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "p4_types.h"
#include "p4tc_common.h"

#define ENV_VAR "INTROSPECTION"

struct mask_ops { int (*parse)(struct parse_state *state, __u32 *offset,
		     const char *argv);
};

int str_to_type(const char *type_str);
struct tkey *p4tc_find_table_key(struct tkey keys[], const char *key_name,
				 __u32 num_keys);
int p4tc_get_table_keys(struct tkey keys[], const char *pname,
			const char *tname, const __u32 tbl_id);

struct hdrfield {
	char name[TEMPLATENAMSZ];
	struct p4_type_s *ty;
	__u32 id;
	__u32 parserid;
	__u16 startbit;
	__u16 endbit;
};

int p4tc_get_act(const char *pname, const char *act_name, __u32 *pipeid,
		 __u32 *act_id);
struct hdrfield *p4tc_find_hdrfield(struct hdrfield fields[],
				    const char *fieldname,
				    __u32 num_fields);
int p4tc_get_header_fields(struct hdrfield fields[], const char *pname,
			   const char *hdrname, __u32 *pipeid);

int p4tc_get_metadata(struct p4_metat_s metadata[]);
int p4tc_get_tables(const char *pname, const char *tname, __u32 *pipeid,
		    __u32 *tbcid);
int p4tc_get_act_params(struct p4_param_s params[], const char *pname,
			const char *act_name, __u32 *pipeid, __u32 *act_id);
int p4tc_get_pipeline_regs(struct p4_reg_s regs[], const char *pname, int *i);
int p4tc_get_regs(struct p4_reg_s regs[]);
#endif
