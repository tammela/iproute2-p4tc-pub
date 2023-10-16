/*
 * p4_tc_template.c		P4 TC Template Management
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <dlfcn.h>

#include "utils.h"
#include "tc_common.h"
#include "tc_util.h"
#include "p4tc_common.h"
#include "p4_types.h"

#include "p4tc_common.h"

static void p4template_usage(void)
{
	fprintf(stderr,
		"usage: tc p4template create | update pipeline/pname [PIPEID] OPTS\n"
		"       tc p4template del | get pipeline/[pname] [PIPEID]\n"
		"Where:  OPTS := NUMTABLES STATE\n"
		"	PIPEID := pipeid <32 bit pipeline id>\n"
		"	NUMTABLES := numtables <16 bit numtables>\n"
		"	STATE := state ready\n"
		"\n");

	exit(-1);
}

static int p4tc_extern_inst_print_param_value(FILE *f, struct p4_type_s *t,
					      struct rtattr *arg, void *mask)
{
	struct rtattr *tb[P4TC_EXT_VALUE_PARAMS_MAX + 1];
	struct p4_type_value val;
	void *value;

	parse_rtattr_nested(tb, P4TC_EXT_VALUE_PARAMS_MAX, arg);

	value = RTA_DATA(tb[P4TC_EXT_PARAMS_VALUE_RAW]);

	val.value = value;
	val.mask = mask;
	if (t->print_p4t)
		t->print_p4t(" value:", "value", &val, f);

	return 0;
}

static int p4tc_extern_inst_print_param(FILE *f, struct rtattr *arg)
{
	__u8 *flags = NULL;
	struct rtattr *tb[P4TC_EXT_PARAMS_MAX + 1];
	struct p4_type_s *t;

	parse_rtattr_nested(tb, P4TC_EXT_PARAMS_MAX, arg);

	if (tb[P4TC_EXT_PARAMS_FLAGS])
		flags = RTA_DATA(tb[P4TC_EXT_PARAMS_FLAGS]);

	if (tb[P4TC_EXT_PARAMS_NAME]) {
		char *name;

		name = RTA_DATA(tb[P4TC_EXT_PARAMS_NAME]);
		if (flags && *flags & P4TC_EXT_PARAMS_FLAG_ISKEY)
			print_string(PRINT_ANY, "name", "\t  %s key", name);
		else
			print_string(PRINT_ANY, "name", "\t  %s ", name);
	}

	if (tb[P4TC_EXT_PARAMS_ID]) {
		__u32 *id;

		id = RTA_DATA(tb[P4TC_EXT_PARAMS_ID]);
		print_uint(PRINT_ANY, "id", " id %u ", *id);
	}

	if (tb[P4TC_EXT_PARAMS_TYPE]) {
		__u32 contain_id;

		contain_id = *((__u32 *) RTA_DATA(tb[P4TC_EXT_PARAMS_TYPE]));
		t = get_p4type_byid(contain_id);
		if (!t) {
			fprintf(stderr, "Unknown param type %d\n", contain_id);
			return -1;
		}

		print_string(PRINT_ANY, "type", "type %s", t->name);
	} else {
		fprintf(stderr, "Must specify params type");
		return -1;
	}

	if (tb[P4TC_EXT_PARAMS_VALUE])
		p4tc_extern_inst_print_param_value(f, t, tb[P4TC_EXT_PARAMS_VALUE],
						   RTA_DATA(tb[P4TC_EXT_PARAMS_VALUE]));

	print_nl();

	return 0;
}

int p4tc_extern_inst_print_params(struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, arg);

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		open_json_object(NULL);
		p4tc_extern_inst_print_param(f, tb[i]);
		close_json_object();
	}

	return 0;
}

static int print_extern_inst_template(struct nlmsghdr *n, struct rtattr *arg,
				      __u32 extid, __u32 instid, FILE *f)
{
	struct rtattr *tb[P4TC_TMPL_EXT_INST_MAX + 1];
	char *extname, *instname;

	parse_rtattr_nested(tb, P4TC_TMPL_EXT_INST_MAX, arg);

	if (tb[P4TC_TMPL_EXT_INST_EXT_NAME]) {
		extname = RTA_DATA(tb[P4TC_TMPL_EXT_INST_EXT_NAME]);
		print_string(PRINT_ANY, "extname",  "    extern name %s\n",
			     extname);
	}

	if (tb[P4TC_TMPL_EXT_INST_NAME]) {
		instname = RTA_DATA(tb[P4TC_TMPL_EXT_INST_NAME]);
		print_string(PRINT_ANY, "extinstname",
			     "    extern instance name %s\n", instname);
	}

	if (tb[P4TC_TMPL_EXT_INST_CONTROL_PARAMS]) {
		print_string(PRINT_FP, NULL, "    Control params: \n", NULL);
		open_json_array(PRINT_JSON, "control_params");
		p4tc_extern_inst_print_params(tb[P4TC_TMPL_EXT_INST_CONTROL_PARAMS], f);
		close_json_array(PRINT_JSON, NULL);
	}

	if (tb[P4TC_TMPL_EXT_INST_CONSTR_PARAMS]) {
		print_string(PRINT_FP, NULL, "    Constructor params: \n", NULL);
		open_json_array(PRINT_JSON, "constructor_params");
		p4tc_extern_inst_print_params(tb[P4TC_TMPL_EXT_INST_CONSTR_PARAMS], f);
		close_json_array(PRINT_JSON, NULL);
	}

	if (tb[P4TC_TMPL_EXT_INST_NUM_ELEMS]) {
		__u32 *num_elems;

		num_elems = RTA_DATA(tb[P4TC_TMPL_EXT_INST_NUM_ELEMS]);
		print_uint(PRINT_ANY, "num_elems",
			   "    Max number of elements %u", *num_elems);
	}

	if (extid)
		print_uint(PRINT_ANY, "extid", "    extern id %u\n", extid);

	if (instid)
		print_uint(PRINT_ANY, "extinstid",
			   "    extern instance id %u\n", instid);

	return 0;
}

static int print_extern_template(struct nlmsghdr *n, struct rtattr *arg,
				   __u32 extid, FILE *f)
{
	struct rtattr *tb[P4TC_TMPL_EXT_MAX + 1];
	char *name;

	parse_rtattr_nested(tb, P4TC_TMPL_EXT_MAX, arg);

	if (tb[P4TC_TMPL_EXT_NAME]) {
		name = RTA_DATA(tb[P4TC_TMPL_EXT_NAME]);
		print_string(PRINT_ANY, "extname",  "    extern name %s\n", name);
	}

	if (tb[P4TC_TMPL_EXT_NUM_INSTS]) {
		__u16 *num_insts;

		num_insts = RTA_DATA(tb[P4TC_TMPL_EXT_NUM_INSTS]);
		print_uint(PRINT_ANY, "num_insts",
			   "    Max number of instances %u", *num_insts);
	}

	if (extid)
		print_uint(PRINT_ANY, "extid", "    extern id %u\n", extid);


	return 0;
}

int p4tc_print_permissions(const char *prefix, __u16 *passed_permissions,
			   const char *suffix, FILE *f)
{
	char permissions[P4TC_CTRL_PERM_C_BIT + 2] = {0};
	int i_str;
	int i;

	for (i = 0; i < P4TC_CTRL_PERM_C_BIT + 1; i++) {
		if (i >= P4TC_CTRL_PERM_X_BIT)
			i_str = P4TC_CTRL_PERM_C_BIT - i;
		else
			i_str = -1 * (i - P4TC_CTRL_PERM_C_BIT);

		switch (i) {
		case P4TC_DATA_PERM_C_BIT:
		case P4TC_CTRL_PERM_C_BIT: {
			if (*passed_permissions & (1 << i))
				permissions[i_str] = 'C';
			else
				permissions[i_str] = '-';
			break;
		}
		case P4TC_DATA_PERM_R_BIT:
		case P4TC_CTRL_PERM_R_BIT: {
			if (*passed_permissions & (1 << i))
				permissions[i_str] = 'R';
			else
				permissions[i_str] = '-';
			break;
		}
		case P4TC_DATA_PERM_U_BIT:
		case P4TC_CTRL_PERM_U_BIT: {
			if (*passed_permissions & (1 << i))
				permissions[i_str] = 'U';
			else
				permissions[i_str] = '-';
			break;
		}
		case P4TC_DATA_PERM_D_BIT:
		case P4TC_CTRL_PERM_D_BIT: {
			if (*passed_permissions & (1 << i))
				permissions[i_str] = 'D';
			else
				permissions[i_str] = '-';
			break;
		}
		case P4TC_DATA_PERM_X_BIT:
		case P4TC_CTRL_PERM_X_BIT: {
			if (*passed_permissions & (1 << i))
				permissions[i_str] = 'X';
			else
				permissions[i_str] = '-';
			break;
		}
		case P4TC_DATA_PERM_P_BIT:
		case P4TC_CTRL_PERM_P_BIT: {
			if (*passed_permissions & (1 << i))
				permissions[i_str] = 'P';
			else
				permissions[i_str] = '-';
			break;
		}
		case P4TC_DATA_PERM_S_BIT:
		case P4TC_CTRL_PERM_S_BIT: {
			if (*passed_permissions & (1 << i))
				permissions[i_str] = 'S';
			else
				permissions[i_str] = '-';
			break;
		}
		}
	}

	print_string(PRINT_FP, NULL, "%s", prefix);
	print_string(PRINT_ANY, "permissions", "permissions %s", permissions);
	print_string(PRINT_FP, NULL, "%s", suffix);

	return 0;
}

static int p4tc_print_table_default_action(struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_TABLE_DEFAULT_ACTION_MAX + 1];

	parse_rtattr_nested(tb, P4TC_TABLE_DEFAULT_ACTION_MAX, arg);

	if (tb[P4TC_TABLE_DEFAULT_ACTION_NOACTION])
		print_string(PRINT_ANY, "actname", "action name %s\n",
			     "NoAction");
	else if (tb[P4TC_TABLE_DEFAULT_ACTION])
		tc_print_action(f, tb[P4TC_TABLE_DEFAULT_ACTION], 1);

	if (tb[P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS]) {
		__u16 *permissions;

		permissions = RTA_DATA(tb[P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS]);
		p4tc_print_permissions("", permissions, "\n", f);
	}

	return 0;
}

static int p4tc_print_tmpl_table_act(struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_TABLE_ACT_MAX  + 1];

	parse_rtattr_nested(tb, P4TC_TABLE_ACT_MAX, arg);

	if (tb[P4TC_TABLE_ACT_NAME]) {
		char *table_act_name;

		table_act_name = RTA_DATA(tb[P4TC_TABLE_ACT_NAME]);
		print_string(PRINT_ANY, "act_name", "        act name %s\n",
			     table_act_name);
	}

	if (tb[P4TC_TABLE_ACT_FLAGS]) {
		__u8 *flags;

		flags = RTA_DATA(tb[P4TC_TABLE_ACT_FLAGS]);
		if (*flags & (1 << P4TC_TABLE_ACTS_DEFAULT_ONLY))
			print_string(PRINT_ANY, "flags",
				     "        act flags %s\n", "defaultonly");
		else if (*flags & (1 << P4TC_TABLE_ACTS_TABLE_ONLY))
			print_string(PRINT_ANY, "flags",
				     "        act flags %s\n", "tableonly");
	}

	return 0;
}

static int p4tc_print_tmpl_table_acts_list(struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, arg);

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		open_json_object(NULL);
		p4tc_print_tmpl_table_act(tb[i], f);
		close_json_object();
		print_nl();
	}

	return 0;
}

static int p4tc_print_table_timer_profile(struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_TIMER_PROFILE_MAX  + 1];

	parse_rtattr_nested(tb, P4TC_TIMER_PROFILE_MAX, arg);

	if (tb[P4TC_TIMER_PROFILE_ID]) {
		__u32 *profile_id;

		profile_id = RTA_DATA(tb[P4TC_TIMER_PROFILE_ID]);
		print_uint(PRINT_ANY, "profile_id", "        profile id %u\n",
			   *profile_id);
	}

	if (tb[P4TC_TIMER_PROFILE_AGING]) {
		__u64 *profile_aging;

		profile_aging = RTA_DATA(tb[P4TC_TIMER_PROFILE_AGING]);
		print_lluint(PRINT_ANY, "profile_aging",
			     "        profile aging %u\n", *profile_aging);
	}

	return 0;
}

static int p4tc_print_table_timer_profiles(struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, arg);

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		open_json_object(NULL);
		p4tc_print_table_timer_profile(tb[i], f);
		close_json_object();
		print_nl();
	}

	return 0;
}

static int p4tc_print_table(struct nlmsghdr *n, struct p4tc_json_pipeline *pipe,
			    struct rtattr *arg, __u32 tbl_id, FILE *f)
{
	struct rtattr *tb[P4TC_TABLE_MAX + 1];

	parse_rtattr_nested(tb, P4TC_TABLE_MAX, arg);

	if (tbl_id) {
		print_uint(PRINT_ANY, "tblid", "    table id %u", tbl_id);
		print_nl();
	}

	if (tb[P4TC_TABLE_NAME])
		print_string(PRINT_ANY, "tname", "    table name %s\n",
			     RTA_DATA(tb[P4TC_TABLE_NAME]));

	if (tb[P4TC_TABLE_KEYSZ]) {
		__u32 *tbl_keysz = RTA_DATA(tb[P4TC_TABLE_KEYSZ]);

		print_uint(PRINT_ANY, "keysz", "     table keysz %u\n",
			   *tbl_keysz);

		print_nl();
	}

	if (tb[P4TC_TABLE_MAX_ENTRIES]) {
		__u32 *tbl_max_entries = RTA_DATA(tb[P4TC_TABLE_MAX_ENTRIES]);

		print_uint(PRINT_ANY, "max_entries", "     max_entries %u\n",
			   *tbl_max_entries);

		print_nl();
	}

	if (tb[P4TC_TABLE_MAX_MASKS]) {
		__u32 *tbl_max_masks = RTA_DATA(tb[P4TC_TABLE_MAX_MASKS]);

		print_uint(PRINT_ANY, "masks", "     masks %u\n",
			   *tbl_max_masks);

		print_nl();
	}

	if (tb[P4TC_TABLE_NUM_ENTRIES]) {
		__u32 *tbl_num_entries = RTA_DATA(tb[P4TC_TABLE_NUM_ENTRIES]);

		print_uint(PRINT_ANY, "entries", "     table entries %u",
			   *tbl_num_entries);

		print_nl();
	}

	if (tb[P4TC_TABLE_PERMISSIONS]) {
		__u16 *tbl_permissions = RTA_DATA(tb[P4TC_TABLE_PERMISSIONS]);

		p4tc_print_permissions("    ", tbl_permissions, "\n", f);
	}

	if (tb[P4TC_TABLE_TYPE]) {
		__u16 *tbl_type = RTA_DATA(tb[P4TC_TABLE_TYPE]);

		switch (*tbl_type) {
		case P4TC_TABLE_TYPE_EXACT:
			print_string(PRINT_ANY, "table_type", "    table type %s\n",
				     "exact");
			break;
		case P4TC_TABLE_TYPE_LPM:
			print_string(PRINT_ANY, "table_type", "    table type %s\n",
				     "lpm");
			break;
		case P4TC_TABLE_TYPE_TERNARY:
			print_string(PRINT_ANY, "table_type", "    table type %s\n",
				     "ternary");
			break;
		default:
			break;
		}
	}

	print_nl();

	if (tb[P4TC_TABLE_DEFAULT_HIT]) {
		print_string(PRINT_FP, NULL,
			     "    default_hit:\n", NULL);
		open_json_object("default_hit");
		p4tc_print_table_default_action(tb[P4TC_TABLE_DEFAULT_HIT], f);
		print_nl();
		close_json_object();
	}

	if (tb[P4TC_TABLE_DEFAULT_MISS]) {
		print_string(PRINT_FP, NULL,
			     "    default_miss:\n", NULL);
		open_json_object("default_miss");
		p4tc_print_table_default_action(tb[P4TC_TABLE_DEFAULT_MISS], f);
		print_nl();
		close_json_object();
	}

	if (tb[P4TC_TABLE_ACTS_LIST]) {
		print_string(PRINT_FP, NULL, "    acts list:\n", NULL);
		open_json_array(PRINT_JSON, "acts_list");
		p4tc_print_tmpl_table_acts_list(tb[P4TC_TABLE_ACTS_LIST], f);
		print_nl();
		close_json_array(PRINT_JSON, NULL);
	}

	if (tb[P4TC_TABLE_NUM_TIMER_PROFILES]) {
		__u32 *num_timer_profiles;

		num_timer_profiles =
			RTA_DATA(tb[P4TC_TABLE_NUM_TIMER_PROFILES]);

		print_uint(PRINT_ANY, "num_timer_profiles",
			   "    num timer profiles %u\n", *num_timer_profiles);
	}

	if (tb[P4TC_TABLE_TIMER_PROFILES]) {
		print_string(PRINT_FP, NULL, "    profiles:\n", NULL);
		open_json_array(PRINT_JSON, "profiles");
		p4tc_print_table_timer_profiles(tb[P4TC_TABLE_TIMER_PROFILES],
						f);
		print_nl();
		close_json_array(PRINT_JSON, NULL);
	}

	if (tb[P4TC_TABLE_ENTRY]) {
		struct rtattr *tb_nest[P4TC_MAX + 1];
		struct p4tc_json_table *table = NULL;

		if (tbl_id) {
			if (pipe) {
				table = p4tc_json_find_table_byid(pipe, tbl_id);
				if (!table) {
					fprintf(stderr, "Unable to find table id %d\n",
						tbl_id);
					return -1;
				}
			}
		}

		parse_rtattr_nested(tb_nest, P4TC_MAX,
				    tb[P4TC_TABLE_ENTRY]);

		if (tb_nest[P4TC_PARAMS]) {
			print_string(PRINT_FP, NULL, "    entry:\n",
				     NULL);
			open_json_object("entry");
			print_nl();
			print_table_entry(n, tb_nest[P4TC_PARAMS], f,
					  "        ", table, tbl_id);
			close_json_object();
		}
	}

	if (tb[P4TC_TABLE_COUNTER]) {
		char *counter_inst_path = RTA_DATA(tb[P4TC_TABLE_COUNTER]);

		print_string(PRINT_ANY, "counter_inst_path", "    counter inst path %s\n",
			     counter_inst_path);
	}

	print_nl();

	return 0;
}

static int p4tc_print_table_flush(struct nlmsghdr *n, struct rtattr *cnt_attr,
				   FILE *F)
{
	const __u32 *cnt = RTA_DATA(cnt_attr);

	print_uint(PRINT_ANY, "ttcount", "    table flush count %u", *cnt);
	print_nl();

	return 0;
}

static int print_action_template(struct nlmsghdr *n, struct rtattr *arg,
				 __u32 a_id, FILE *f)
{
	struct action_util au = {0};
	struct rtattr *tb[P4TC_ACT_MAX + 1];

	parse_rtattr_nested(tb, P4TC_ACT_MAX, arg);

	if (tb[P4TC_ACT_NAME]) {
		const char *name = RTA_DATA(tb[P4TC_ACT_NAME]);

		print_string(PRINT_ANY, "aname", "    template action name %s\n", name);
		strlcpy(au.id, RTA_DATA(tb[P4TC_ACT_NAME]),
			RTA_PAYLOAD(tb[P4TC_ACT_NAME]));
	} else {
		fprintf(stderr, "Must specify action name\n");
		return -1;
	}

	if (a_id)
		print_uint(PRINT_ANY, "actid", "    action id %u\n", a_id);

	if (tb[P4TC_ACT_PARMS]) {
		print_string(PRINT_FP, NULL, "\n\t params:\n", "");
		open_json_array(PRINT_JSON, "params");
		print_dyna_parms(&au, tb[P4TC_ACT_PARMS], f);
		close_json_array(PRINT_JSON, NULL);
	}

	if (tb[P4TC_ACT_NUM_PREALLOC]) {
		const __u32 *num_prealloc = RTA_DATA(tb[P4TC_ACT_NUM_PREALLOC]);

		print_uint(PRINT_ANY, "prealloc", "prealloc %u\n",
			   *num_prealloc);
	}

	return 0;
}

static int print_action_template_flush(struct nlmsghdr *n,
				       struct rtattr *cnt_attr,
				       FILE *f)
{
	const __u32 *cnt = RTA_DATA(cnt_attr);

	print_uint(PRINT_ANY, "count", "    action template flush count %u",
		   *cnt);
	print_nl();

	return 0;
}

static int print_pipeline(struct nlmsghdr *n, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[P4TC_PIPELINE_MAX + 1];

	parse_rtattr_nested(tb, P4TC_PIPELINE_MAX, arg);

	if (tb[P4TC_PIPELINE_NUMTABLES]) {
		__u16 num_tables =
		    *((__u16 *) RTA_DATA(tb[P4TC_PIPELINE_NUMTABLES]));
		print_uint(PRINT_ANY, "pnumtables", "    num_tables %u",
			   num_tables);
		print_nl();
	}

	if (tb[P4TC_PIPELINE_STATE]) {
		__u8 state = *((__u8 *) RTA_DATA(tb[P4TC_PIPELINE_STATE]));

		if (state == P4TC_STATE_NOT_READY)
			print_string(PRINT_ANY, "pstate", "    state is not ready",
				     "not ready");
		else if (state == P4TC_STATE_READY)
			print_string(PRINT_ANY, "pstate", "    state is ready",
				     "ready");
		print_nl();
	}

	return 0;
}

static int print_pipeline_dump_1(struct nlmsghdr *n, struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_PIPELINE_MAX + 1];

	parse_rtattr_nested(tb, P4TC_PIPELINE_MAX, arg);

	if (tb[P4TC_PIPELINE_NAME])
		print_string(PRINT_ANY, "pname", "    pipeline name %s\n",
			     RTA_DATA(tb[P4TC_PIPELINE_NAME]));

	return 0;
}

static int print_p4tmpl_1(struct nlmsghdr *n, struct p4tc_json_pipeline *pipe,
			  __u16 cmd, struct rtattr *arg,
			  struct p4tcmsg *t, FILE *f)
{
	struct rtattr *tb[P4TC_MAX + 1];
	__u32 obj = t->obj;
	__u32 *ids = NULL;

	parse_rtattr_nested(tb, P4TC_MAX, arg);

	switch (obj) {
	case P4TC_OBJ_PIPELINE:
		if (cmd == RTM_GETP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
			print_pipeline_dump_1(n, tb[P4TC_PARAMS], f);
		else
			print_pipeline(n, f, tb[P4TC_PARAMS]);
		break;
	case P4TC_OBJ_TABLE:
		if (cmd == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
			p4tc_print_table_flush(n, tb[P4TC_COUNT], f);
		else {
			if (tb[P4TC_PATH]) {
				ids = RTA_DATA(tb[P4TC_PATH]);
				p4tc_print_table(n, pipe, tb[P4TC_PARAMS],
						 ids[0], f);
			} else {
				p4tc_print_table(n, pipe, tb[P4TC_PARAMS], 0,
						 f);
			}
		}
		break;
	case P4TC_OBJ_ACT:
		ids = RTA_DATA(tb[P4TC_PATH]);
		if (cmd == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
			print_action_template_flush(n, tb[P4TC_COUNT], f);
		else {
			if (tb[P4TC_PATH])
				print_action_template(n, tb[P4TC_PARAMS],
						      ids[0], f);
			else
				print_action_template(n, tb[P4TC_PARAMS], 0, f);
		}
		break;
	case P4TC_OBJ_EXT:
		ids = RTA_DATA(tb[P4TC_PATH]);
		if (cmd == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT)) {
			fprintf(stderr, "Not implemented yet\n");
		} else {
			if (tb[P4TC_PATH])
				print_extern_template(n, tb[P4TC_PARAMS],
						      ids[0], f);
			else
				print_extern_template(n, tb[P4TC_PARAMS], 0, f);
		}
		break;
	case P4TC_OBJ_EXT_INST:
		ids = RTA_DATA(tb[P4TC_PATH]);
		if (cmd == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT)) {
			fprintf(stderr, "Not implemented yet\n");
		} else {
			if (tb[P4TC_PATH])
				print_extern_inst_template(n, tb[P4TC_PARAMS],
							   ids[0], ids[1], f);
			else
				print_extern_inst_template(n, tb[P4TC_PARAMS],
							   0, 0, f);
		}
		break;
	default:
		break;
	}

	return 0;
}

#define TMPL_ARRAY_IS_EMPTY(tb) (!(tb[TMPL_ARRAY_START_IDX]))

static int print_p4tmpl_array(struct nlmsghdr *n,
			      struct p4tc_json_pipeline *pipe, __u16 cmd,
			      struct rtattr *nest, struct p4tcmsg *t,
			      void *arg)
{
	int ret = 0;
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, nest);
	if (TMPL_ARRAY_IS_EMPTY(tb))
		return 0;

	open_json_array(PRINT_JSON, "templates");
	for (i = TMPL_ARRAY_START_IDX; i < P4TC_MSGBATCH_SIZE + 1 && tb[i];
	     i++) {
		open_json_object(NULL);
		print_p4tmpl_1(n, pipe, cmd, tb[i], t, (FILE *)arg);
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);

	return ret;
}

int print_p4tmpl(struct nlmsghdr *n, void *arg)
{
	struct p4tc_json_pipeline *pipe = NULL;
	struct rtattr *tb[P4TC_ROOT_MAX + 1];
	struct p4tcmsg *t = NLMSG_DATA(n);
	int len;

	len = n->nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*t));

	open_json_object(NULL);
	switch (n->nlmsg_type) {
	case RTM_CREATEP4TEMPLATE:
		if (n->nlmsg_flags & NLM_F_REPLACE)
			print_bool(PRINT_ANY, "replaced", "replaced ",
				   true);
		else
			print_bool(PRINT_ANY, "created", "created ",
				   true);
		break;
	case RTM_DELP4TEMPLATE:
		print_bool(PRINT_ANY, "deleted", "deleted ", true);
		break;
	}

	parse_rtattr_flags(tb, P4TC_ROOT_MAX, P4TC_RTA(t), len, NLA_F_NESTED);

	switch (t->obj) {
	case P4TC_OBJ_PIPELINE:
		print_string(PRINT_ANY, "obj", "templates obj type %s\n",
			     "pipeline");
		break;
	case P4TC_OBJ_TABLE:
		print_string(PRINT_ANY, "obj", "templates obj type %s\n",
			     "table");
		break;
	case P4TC_OBJ_ACT:
		print_string(PRINT_ANY, "obj", "template obj type %s\n",
			     "action template");
		break;
	case P4TC_OBJ_EXT:
		print_string(PRINT_ANY, "obj", "template obj type %s\n",
			     "extern");
		break;
	case P4TC_OBJ_EXT_INST:
		print_string(PRINT_ANY, "obj", "template obj type %s\n",
			     "extern instance");
		break;
	}

	if (tb[P4TC_ROOT_PNAME]) {
		char *pname = RTA_DATA(tb[P4TC_ROOT_PNAME]);

		if (t->obj != P4TC_OBJ_EXT)
			pipe = p4tc_json_import(pname);

		print_string(PRINT_ANY, "pname", "pipeline name %s", pname);
		print_nl();
	}

	if (t->pipeid) {
		print_uint(PRINT_ANY, "pipeid", "pipeline id %u", t->pipeid);
		print_nl();
	}

	if (tb[P4TC_ROOT]) {
		if (n->nlmsg_type == RTM_GETP4TEMPLATE &&
		    (n->nlmsg_flags & NLM_F_ROOT)) {
			close_json_object();
			open_json_object(NULL);
			print_p4tmpl_array(n, pipe, n->nlmsg_type,
					   tb[P4TC_ROOT], t, arg);
			close_json_object();
		} else {
			print_p4tmpl_1(n, pipe, n->nlmsg_type, tb[P4TC_ROOT], t,
				       arg);
			close_json_object();
		}
	}

	if (pipe)
		p4tc_json_free_pipeline(pipe);

	return 0;
}

static int parse_action_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			     char *p4tcpath[], int cmd, unsigned int *flags)
{
	char *actname = NULL, *tblactname = NULL, *tblname = NULL;
	char full_actname[ACTNAMSIZ] = {0};
	__u32 pipeid = 0, actid = 0;
	struct action_util a = {0};
	__u32 prealloc_acts = 0;
	char **argv = *argv_p;
	struct rtattr *tail;
	int argc = *argc_p;
	int ret = 0;
	char *cbname;

	cbname = p4tcpath[PATH_CBNAME_IDX];
	if (p4tcpath[PATH_TBLANAME_IDX]) {
		tblname = p4tcpath[PATH_TBLNAME_IDX];
		tblactname = p4tcpath[PATH_TBLANAME_IDX];
	} else {
		actname = p4tcpath[PATH_PIPEANAME_IDX];
	}

	if (cbname && actname)
		ret = concat_cb_name(full_actname, cbname, actname, ACTNAMSIZ);
	else if (cbname && tblname && tblactname)
		ret = snprintf(full_actname, ACTNAMSIZ, "%s/%s/%s", cbname,
			       tblname, tblactname) >= ACTNAMSIZ ? -1 : 0;
	else if (cbname)
		ret = try_strncpy(full_actname, cbname, ACTNAMSIZ);

	if (ret < 0) {
		fprintf(stderr, "Action name too long\n");
		return -1;
	}

	tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

	while (argc > 0) {
		if (strcmp(*argv, "pipeid") == 0) {
			NEXT_ARG();
			if (get_u32(&pipeid, *argv, 10) < 0)
				return -1;
		} else if (strcmp(*argv, "actid") == 0) {
			NEXT_ARG();
			if (get_u32(&actid, *argv, 10) < 0)
				return -1;
		} else if (strcmp(*argv, "num_prealloc_acts") == 0) {
			NEXT_ARG();
			if (get_u32(&prealloc_acts, *argv, 0) < 0)
				return -1;
		} else {
			if (parse_dyna(&argc, &argv, false, a.id, n) < 0)
				return -1;
		}
		argv++;
		argc--;
	}
	if (!STR_IS_EMPTY(full_actname))
		addattrstrz(n, MAX_MSG, P4TC_ACT_NAME, full_actname);
	if (prealloc_acts)
		addattr32(n, MAX_MSG, P4TC_ACT_NUM_PREALLOC, prealloc_acts);

	addattr_nest_end(n, tail);
	if (actid)
		addattr32(n, MAX_MSG, P4TC_PATH, actid);
	if (!actid && !cbname && !actname)
		*flags |= NLM_F_ROOT;

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

struct param {
	char name[EXTPARAMNAMSIZ];
	__u32 id;
	__u32 type;
	__u32 bitsz;
	__u8 flags;
};

static int p4tc_extern_param_copy_name(char *dst_pname, char *src_pname)
{
	if (strnlen(src_pname, EXTPARAMNAMSIZ) == EXTPARAMNAMSIZ)
		return -1;

	strcpy(dst_pname, src_pname);

	return 0;
}

static int p4tc_extern_inst_add_param_val(struct param *param,
					  const char *value, struct nlmsghdr *n)
{
	int ret = 0;
	struct p4_type_value val;
	struct rtattr *nest_val;
	struct p4_type_s *t;
	void *new_value;
	void *new_mask;
	__u32 sz;

	t = get_p4type_byid(param->type);
	if (!t) {
		fprintf(stderr, "Unknown param type %d\n", param->type);
		return -1;
	}
	sz = t->bitsz >> 3;
	new_value = calloc(1, sz);
	if (!new_value)
		return -1;
	new_mask = calloc(1, sz);
	if (!new_mask) {
		ret = -1;
		goto free_value;
	}

	val.value = new_value;
	val.mask = new_mask;
	val.bitsz = param->bitsz;
	if (t->parse_p4t &&
	    t->parse_p4t(&val, value, 0) < 0) {
		ret = -1;
		goto free_mask;
	}

	nest_val = addattr_nest(n, MAX_MSG,
				P4TC_EXT_PARAMS_VALUE | NLA_F_NESTED);
	addattr_l(n, MAX_MSG, P4TC_EXT_PARAMS_VALUE_RAW, new_value, sz);
	addattr_nest_end(n, nest_val);

free_mask:
	free(new_mask);
free_value:
	free(new_value);

	return ret;
}

static int
p4tc_extern_add_key_value(struct param *param, const char *value,
			  struct nlmsghdr *n)
{
	addattrstrz(n, MAX_MSG, P4TC_EXT_PARAMS_NAME, param->name);

	return p4tc_extern_inst_add_param_val(param, value, n);
}

static int p4tc_extern_inst_add_param(struct param *param, char ***argv_p,
				      int *argc_p, bool add_raw_value,
				      struct nlmsghdr *n)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret = 0;

	addattrstrz(n, MAX_MSG, P4TC_EXT_PARAMS_NAME, param->name);
	if (param->id)
		addattr32(n, MAX_MSG, P4TC_EXT_PARAMS_ID, param->id);
	if (param->type)
		addattr32(n, MAX_MSG, P4TC_EXT_PARAMS_TYPE, param->type);
	if (param->bitsz)
		addattr16(n, MAX_MSG, P4TC_EXT_PARAMS_BITSZ, param->bitsz);
	if (param->flags)
		addattr8(n, MAX_MSG, P4TC_EXT_PARAMS_FLAGS, param->flags);

	if (add_raw_value) {
		char *value = *argv;

		if (p4tc_extern_inst_add_param_val(param, value, n) < 0)
			return -1;
	} else {
		if (argc && strcmp(*argv, "default_value") == 0) {
			NEXT_ARG();
			if (p4tc_extern_inst_add_param_val(param, *argv, n) < 0)
				return -1;
			argv++;
			argc--;
		}
	}

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

int p4tc_extern_parse_inst_param(int *argc_p, char ***argv_p,
				 bool add_raw_value, int *parms_count,
				 struct p4tc_json_extern_insts_list *inst,
				 struct nlmsghdr *n)
{
	struct p4tc_json_extern_insts_data *param_data = NULL;
	struct param param = {0};
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail;
	int err = 0;

	if (strcmp(*argv, "tc_key") == 0)
		param.flags |= P4TC_EXT_PARAMS_FLAG_ISKEY;
	else if (strcmp(*argv, "tc_data_scalar") == 0)
		param.flags |= P4TC_EXT_PARAMS_FLAG_IS_DATASCALAR;

	NEXT_ARG();
	if (p4tc_extern_param_copy_name(param.name, *argv) < 0) {
		fprintf(stderr, "Param name too big");
		return -E2BIG;
	}

	if (inst)
		param_data = p4tc_json_find_extern_data(inst, param.name);

	if (param_data) {
		struct p4_type_s *t;

		t = get_p4type_byarg(param_data->type, &param.bitsz);
		if (!t) {
			fprintf(stderr, "Invalid type %s\n", param_data->type);
			return -1;
		}
		param.type = t->containid;

		param.id = param_data->id;
	} else if (param.flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
		struct p4_type_s *t;

		t = get_p4type_byname("bit32");
		param.type = t->containid;
		param.bitsz = t->bitsz;
	}

	NEXT_ARG();

	/* If user stil wants to specify type and id, let them overwrite it */
	while (argc > 0) {
		if (strcmp(*argv, "type") == 0) {
			struct p4_type_s *t;

			NEXT_ARG();
			t = get_p4type_byarg(*argv, &param.bitsz);
			if (!t) {
				fprintf(stderr, "Invalid type %s\n", *argv);
				return -1;
			}
			param.type = t->containid;
		} else if (strcmp(*argv, "id") == 0) {
			__u32 id;

			NEXT_ARG();
			if (get_u32(&id, *argv, 10)) {
				fprintf(stderr, "Invalid id %s\n",
					*argv);
				return -1;
			}
			param.id = id;
		} else {
			break;
		}
		argv++;
		argc--;
	}

	if (add_raw_value && param.flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
		err = p4tc_extern_add_key_value(&param, *argv, n);
		if (err < 0)
			return err;

		goto out;
	}

	tail = addattr_nest(n, MAX_MSG, *parms_count | NLA_F_NESTED);
	if (p4tc_extern_inst_add_param(&param, &argv, &argc, add_raw_value, n) < 0)
		return -1;

	addattr_nest_end(n, tail);
	(*parms_count)++;

out:
	*argc_p = argc;
	*argv_p = argv;

	return err;
}

static int parse_extern_inst_params(int *argc_p, char ***argv_p,
				    struct nlmsghdr *n)
{
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	int parms_count = 1;
	int argc = *argc_p;

	while (argc > 0) {
		if (strcmp(*argv, "param") == 0 ||
		    strcmp(*argv, "tc_key") == 0 ||
		    strcmp(*argv, "tc_data_scalar") == 0) {
			if (p4tc_extern_parse_inst_param(&argc, &argv, false,
							 &parms_count, NULL, n) < 0)
				return -1;

			if (argc && (strcmp(*argv, "param") == 0 ||
				     strcmp(*argv, "tc_key") == 0 ||
				     strcmp(*argv, "tc_data_scalar") == 0))
				continue;
		} else {
			break;
		}
	}
	if (tail)
		addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int parse_extern_inst_constr_params(int *argc_p, char ***argv_p,
					   struct nlmsghdr *n)
{
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	int parms_count = 1;
	int argc = *argc_p;

	while (argc > 0) {
		if (strcmp(*argv, "param") == 0) {
			if (p4tc_extern_parse_inst_param(&argc, &argv, true,
							 &parms_count, NULL, n) < 0)
				return -1;

			if ((strcmp(*argv, "param") == 0))
				continue;
		} else {
			break;
		}
	}
	if (tail)
		addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int parse_extern_inst_data(int *argc_p, char ***argv_p,
				  struct nlmsghdr *n, char *p4tcpath[],
				  int cmd, unsigned int *flags)
{
	struct rtattr *tail = NULL, *tail_control = NULL, *tail_constrs = NULL;
	__u32 extid = 0, instid = 0, pipeid = 0;
	bool parsed_num_elems = false;
	bool tbl_bindable = false;
	char **argv = *argv_p;
	int argc = *argc_p;
	char *extname, *instname;
	__u32 ids[2] = {0};
	__u32 num_elems = 0;

	extname = p4tcpath[PATH_EXTNAME_IDX];
	instname = p4tcpath[PATH_EXTINSTNAME_IDX];

	while (argc > 0) {
		if (strcmp(*argv, "extid") == 0) {
			NEXT_ARG();
			if (get_u32(&extid, *argv, 0) < 0)
				return -1;
		} else if (strcmp(*argv, "instid") == 0) {
			NEXT_ARG();
			if (get_u32(&instid, *argv, 0) < 0)
				return -1;
		} else if (strcmp(*argv, "pipeid") == 0) {
			NEXT_ARG();
			if (get_u32(&pipeid, *argv, 0) < 0)
				return -1;
		} else if (strcmp(*argv, "tc_numel") == 0) {
			NEXT_ARG();
			if (get_u32(&num_elems, *argv, 0) < 0)
				return -1;
			parsed_num_elems = true;
		} else if (strcmp(*argv, "control_path") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "param") && strcmp(*argv, "tc_key") &&
			    strcmp(*argv, "tc_data_scalar")) {
				fprintf(stderr,
					"Illegal arg %s after control_path\n",
					*argv);
				return -1;
			}
			if (!tail)
				tail = addattr_nest(n, MAX_MSG,
						    P4TC_PARAMS | NLA_F_NESTED);

			if (tail_constrs) {
				addattr_nest_end(n, tail_constrs);
				tail_constrs = NULL;
			}

			if (!tail_control) {
				int attr_id;

				attr_id = P4TC_TMPL_EXT_INST_CONTROL_PARAMS | NLA_F_NESTED;
				tail_control = addattr_nest(n, MAX_MSG,
							    attr_id);
			}
			if (parse_extern_inst_params(&argc, &argv, n) < 0)
				return -1;
		} else if (strcmp(*argv, "tbl_bindable") == 0) {
			tbl_bindable = true;
		} else if (strcmp(*argv, "constructor") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "param")) {
				fprintf(stderr,
					"Illegal arg %s after control_path\n",
					*argv);
				return -1;
			}
			if (!tail)
				tail = addattr_nest(n, MAX_MSG,
						    P4TC_PARAMS | NLA_F_NESTED);

			if (tail_control) {
				addattr_nest_end(n, tail_control);
				tail_control = NULL;
			}
			if (!tail_constrs) {
				int attr_id;

				attr_id = P4TC_TMPL_EXT_INST_CONSTR_PARAMS | NLA_F_NESTED;
				tail_constrs = addattr_nest(n, MAX_MSG,
							    attr_id);
			}
			if (parse_extern_inst_constr_params(&argc, &argv, n) < 0)
				return -1;
		}

		argv++;
		argc--;
	}

	if (tail_control)
		addattr_nest_end(n, tail_control);
	if (tail_constrs)
		addattr_nest_end(n, tail_constrs);

	if (!instname && !instid)
		*flags |= NLM_F_ROOT;

	if (!tail)
		tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

	if (extname)
		addattrstrz(n, MAX_MSG, P4TC_TMPL_EXT_INST_EXT_NAME, extname);

	if (instname)
		addattrstrz(n, MAX_MSG, P4TC_TMPL_EXT_INST_NAME, instname);

	if (parsed_num_elems)
		addattr32(n, MAX_MSG, P4TC_TMPL_EXT_INST_NUM_ELEMS,
			  num_elems);

	if (tbl_bindable)
		addattr8(n, MAX_MSG, P4TC_TMPL_EXT_INST_TABLE_BINDABLE, 1);

	addattr_nest_end(n, tail);

	ids[0] = extid;
	ids[1] = instid;
	if (extid || instid)
		addattr_l(n, MAX_MSG, P4TC_PATH, ids, sizeof(ids));

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

static int parse_extern_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			     char *p4tcpath[], int cmd, unsigned int *flags)
{
	bool parsed_num_insts = false;
	bool has_exec_method = false;
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	int argc = *argc_p;
	__u16 numinsts = 0;
	__u32 ext_id = 0;
	char *pname;
	char *extname;

	pname = p4tcpath[PATH_PNAME_IDX];
	extname = p4tcpath[PATH_EXTNAME_IDX];

	if (strncmp(pname, "root", P4TC_PIPELINE_NAMSIZ)) {
		fprintf(stderr, "Pipeline name for extern should be root\n");
		return -1;
	}

	while (argc > 0) {
		if (strcmp(*argv, "ext_id") == 0) {
			NEXT_ARG();
			if (get_u32(&ext_id, *argv, 0) < 0)
				return -1;
		} else if (strcmp(*argv, "numinstances") == 0) {
			NEXT_ARG();
			if (get_u16(&numinsts, *argv, 0) < 0)
				return -1;
			parsed_num_insts = true;
		} else  if (strcmp(*argv, "has_exec_method") == 0) {
			has_exec_method = true;
		}

		argv++;
		argc--;
	}

	if (extname || ext_id)
		tail = tail ?: addattr_nest(n, MAX_MSG,
					    P4TC_PARAMS | NLA_F_NESTED);
	else
		*flags |= NLM_F_ROOT;

	if (extname)
		addattrstrz(n, MAX_MSG, P4TC_TMPL_EXT_NAME, extname);

	if (parsed_num_insts)
		addattr16(n, MAX_MSG, P4TC_TMPL_EXT_NUM_INSTS, numinsts);

	if (has_exec_method)
		addattr8(n, MAX_MSG, P4TC_TMPL_EXT_HAS_EXEC_METHOD,
			 has_exec_method);

	if (tail)
		addattr_nest_end(n, tail);

	if (ext_id)
		addattr32(n, MAX_MSG, P4TC_PATH, ext_id);

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int parse_tmpl_table_action(int *argc_p, char ***argv_p,
				   struct nlmsghdr *n, __u32 attr_id)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail;

	tail = addattr_nest(n, MAX_MSG, attr_id | NLA_F_NESTED);
	while (argc > 0) {
		if (strcmp(*argv, "name") == 0) {
			NEXT_ARG();
			addattrstrz(n, MAX_MSG, P4TC_TABLE_ACT_NAME,
				    *argv);
			NEXT_ARG_FWD();
		} else if (strcmp(*argv, "flags") == 0) {
			__u8 flags;

			NEXT_ARG();
			if (strcmp(*argv, "defaultonly") == 0) {
				flags = (1 << P4TC_TABLE_ACTS_DEFAULT_ONLY);
			} else if (strcmp(*argv, "tableonly") == 0) {
				flags = (1 << P4TC_TABLE_ACTS_TABLE_ONLY);
			} else {
				fprintf(stderr, "Unknown allowed action flags\n");
				return -1;
			}
			addattr8(n, MAX_MSG, P4TC_TABLE_ACT_FLAGS,
				 flags);
			NEXT_ARG_FWD();
		} else {
			break;
		}
	}
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int parse_tmpl_table_acts_list(int *argc_p, char ***argv_p,
				      struct nlmsghdr *n, __u32 attr_id)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail;
	int i = 1;
	int ret;

	tail = addattr_nest(n, MAX_MSG, attr_id | NLA_F_NESTED);
	while (argc > 0) {
		if (strcmp(*argv, "act") == 0) {
			NEXT_ARG();
			ret = parse_tmpl_table_action(&argc, &argv, n, i);
			if (ret < 0)
				return ret;
			goto increment_i;
		} else {
			break;
		}

		NEXT_ARG_FWD();

increment_i:
		i++;
	}
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

int parse_table_default_action(int *argc_p, char ***argv_p,
			       struct nlmsghdr *n, __u32 attr_id)
{
	const __u16 defact_attr = P4TC_TABLE_DEFAULT_ACTION | NLA_F_NESTED;
	struct rtattr *tail;
	char **argv = *argv_p;
	int argc = *argc_p;
	__u16 permissions;

	tail = addattr_nest(n, MAX_MSG, attr_id | NLA_F_NESTED);
	while (argc > 0) {
		if (strcmp(*argv, "action") == 0) {
			int ret;

			NEXT_ARG();
			if (strcmp(*argv, "NoAction") == 0) {
				addattr8(n, MAX_MSG,
					 P4TC_TABLE_DEFAULT_ACTION_NOACTION,
					 1);
			} else {
				PREV_ARG();
				ret = parse_action(&argc, &argv, defact_attr,
						   n);
				if (ret) {
					fprintf(stderr, "Illegal action\n");
					return -1;
				}
			}
		} else if (strcmp(*argv, "permissions") == 0) {
			NEXT_ARG();
			if (get_u16(&permissions, *argv, 16) < 0)
				return -1;
			addattr16(n, MAX_MSG,
				  P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS,
		permissions);
		}
		NEXT_ARG_FWD();
	}
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

#define PRINT_TABLE_ATTR_CANT_BE_ZERO(attr) \
	fprintf(stderr, "table %s cannot be zero\n", attr)

static int parse_table_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			    char *p4tcpath[], int cmd, unsigned int *flags)
{
	__u32 tbl_max_masks = 0, tbl_max_entries = 0, tbl_keysz = 0;
	char *pname, *cbname, *tblname, *ext_inst_path = NULL;
	char full_tblname[P4TC_TABLE_NAMSIZ] = {0};
	bool parsed_permissions = false;
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	__u16 tbl_permissions;
	int argc = *argc_p;
	__u64 tbl_aging = 0;
	__u8 tbl_type = 0;
	__u32 tbl_id = 0;
	__u32 pipeid = 0;
	int ret = 0;

	pname = p4tcpath[PATH_PNAME_IDX];
	cbname = p4tcpath[PATH_CBNAME_IDX];
	tblname = p4tcpath[PATH_TBLNAME_IDX];

	if (cmd != RTM_GETP4TEMPLATE) {
		tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);
	}

	if (cbname && tblname) {
		ret = concat_cb_name(full_tblname, cbname, tblname,
				     P4TC_TABLE_NAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "table name too long\n");
			return -1;
		}
	}

	while (argc > 0) {
		if (cmd == RTM_CREATEP4TEMPLATE ||
		    cmd == RTM_UPDATEP4TEMPLATE) {
			if (strcmp(*argv, "tblid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbl_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "keysz") == 0) {
				NEXT_ARG();
				if (get_u32(&tbl_keysz, *argv, 10) < 0)
					return -1;
				if (!tbl_keysz) {
					PRINT_TABLE_ATTR_CANT_BE_ZERO("keysz");
					return -1;
				}
			} else if (strcmp(*argv, "tentries") == 0) {
				NEXT_ARG();
				if (get_u32(&tbl_max_entries, *argv, 10) < 0)
					return -1;
				if (!tbl_max_entries) {
					PRINT_TABLE_ATTR_CANT_BE_ZERO("max entries");
					return -1;
				}
			} else if (strcmp(*argv, "nummasks") == 0) {
				NEXT_ARG();
				if (get_u32(&tbl_max_masks, *argv, 10) < 0)
					return -1;
				if (!tbl_max_masks) {
					PRINT_TABLE_ATTR_CANT_BE_ZERO("max masks");
					return -1;
				}
			} else if (strcmp(*argv, "type") == 0) {
				NEXT_ARG();
				if (strcmp(*argv, "lpm") == 0) {
					tbl_type = P4TC_TABLE_TYPE_LPM;
				} else if (strcmp(*argv, "exact") == 0) {
					tbl_type = P4TC_TABLE_TYPE_EXACT;
				} else if (strcmp(*argv, "ternary") == 0) {
					tbl_type = P4TC_TABLE_TYPE_TERNARY;
				} else {
					fprintf(stderr, "Unknown table type %s\n",
						*argv);
					return -1;
				}
			} else if (strcmp(*argv, "aging") == 0) {
				NEXT_ARG();
				if (get_u64(&tbl_aging, *argv, 0) < 0)
					return -1;
				if (!tbl_aging) {
					PRINT_TABLE_ATTR_CANT_BE_ZERO("aging");
					return -1;
				}
			} else if (strcmp(*argv, "num_timer_profiles") == 0) {
				__u32 num_timer_profiles;

				NEXT_ARG();
				if (get_u32(&num_timer_profiles, *argv, 0) < 0)
					return -1;
				addattr32(n, MAX_MSG,
					  P4TC_TABLE_NUM_TIMER_PROFILES,
					  num_timer_profiles);
			} else if (strcmp(*argv, "pna_direct_counter") == 0) {
				NEXT_ARG();
				ext_inst_path = *argv;
			} else if (strcmp(*argv, "default_hit_action") == 0) {
				argv++;
				argc--;
				if (parse_table_default_action(&argc, &argv, n,
							       P4TC_TABLE_DEFAULT_HIT))
					return -1;
				continue;
			} else if (strcmp(*argv, "default_miss_action") == 0) {
				argv++;
				argc--;
				if (parse_table_default_action(&argc, &argv, n,
							       P4TC_TABLE_DEFAULT_MISS))
					return -1;
				continue;
			} else if (strcmp(*argv, "permissions") == 0) {
				NEXT_ARG();
				if (get_u16(&tbl_permissions, *argv, 16) < 0)
					return -1;
				parsed_permissions = true;
			} else if (strcmp(*argv, "table_acts") == 0) {
				NEXT_ARG();
				if (parse_tmpl_table_acts_list(&argc, &argv, n,
							       P4TC_TABLE_ACTS_LIST) < 0)
					return -1;
				continue;
			} else if (strcmp(*argv, "entry") == 0) {
				struct parse_state state = {0};
				__u32 offset = 0;
				struct rtattr *entries;
				__u32 tmp_ids[2];

				entries = addattr_nest(n, MAX_MSG,
						       P4TC_TABLE_ENTRY | NLA_F_NESTED);

				NEXT_ARG();
				ret = parse_new_table_entry(&argc, &argv, n,
							    &state, p4tcpath,
							    pname, tmp_ids,
							    &offset);
				if (ret < 0)
					return -1;

				if (state.has_parsed_keys) {
					addattr_l(n, MAX_MSG, P4TC_ENTRY_KEY_BLOB,
						  state.keyblob, offset);
					addattr_l(n, MAX_MSG, P4TC_ENTRY_MASK_BLOB,
						  state.maskblob, offset);
				}
				addattr_nest_end(n, entries);
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
		} else {
			if (strcmp(*argv, "tblid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbl_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (cmd == RTM_DELP4TEMPLATE &&
				   strcmp(*argv, "default_hit_action") == 0) {
				struct rtattr *nest_hit_act;

				argv++;
				argc--;
				nest_hit_act = addattr_nest(n, MAX_MSG,
							    P4TC_TABLE_DEFAULT_HIT | NLA_F_NESTED);
				addattr_nest_end(n, nest_hit_act);
				continue;
			} else if (cmd == RTM_DELP4TEMPLATE &&
				   strcmp(*argv, "default_miss_action") == 0) {
				struct rtattr *nest_miss_act;

				argv++;
				argc--;
				nest_miss_act = addattr_nest(n, MAX_MSG,
							    P4TC_TABLE_DEFAULT_MISS | NLA_F_NESTED);
				addattr_nest_end(n, nest_miss_act);
				continue;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
		}
		argv++;
		argc--;
	}

	if (!cbname && !tblname && !tbl_id)
		*flags |= NLM_F_ROOT;
	else if (cmd == RTM_GETP4TEMPLATE)
		tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

	if ((cmd == RTM_CREATEP4TEMPLATE  || cmd == RTM_UPDATEP4TEMPLATE)) {
		if (tbl_keysz)
			addattr32(n, MAX_MSG, P4TC_TABLE_KEYSZ, tbl_keysz);
		if (tbl_max_entries)
			addattr32(n, MAX_MSG, P4TC_TABLE_MAX_ENTRIES,
				  tbl_max_entries);
		if (tbl_max_masks)
			addattr32(n, MAX_MSG, P4TC_TABLE_MAX_MASKS,
				  tbl_max_masks);
		if (parsed_permissions)
			addattr16(n, MAX_MSG, P4TC_TABLE_PERMISSIONS,
				  tbl_permissions);
		if (tbl_type)
			addattr8(n, MAX_MSG, P4TC_TABLE_TYPE, tbl_type);
	}

	ret = 0;
	if (!STR_IS_EMPTY(full_tblname))
		addattrstrz(n, MAX_MSG, P4TC_TABLE_NAME, full_tblname);

	if (ext_inst_path)
		addattrstrz(n, MAX_MSG, P4TC_TABLE_COUNTER, ext_inst_path);

	if (tail)
		addattr_nest_end(n, tail);

	if (tbl_id)
		addattr32(n, MAX_MSG, P4TC_PATH, tbl_id);

out:
	*argc_p = argc;
	*argv_p = argv;

	if (ret < 0)
		return ret;
	return pipeid;
}

static int parse_pipeline_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			       int cmd, unsigned int flags)
{
	char **argv = *argv_p;
	struct rtattr *nest;
	int argc = *argc_p;
	__u32 pipeid = 0;
	__u16 numtables;

	if (cmd == RTM_CREATEP4TEMPLATE ||
	    cmd == RTM_UPDATEP4TEMPLATE) {
		nest = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

		while (argc > 0) {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "numtables") == 0) {
				NEXT_ARG();
				if (get_u16(&numtables, *argv, 10) < 0)
					return -1;

				addattr16(n, MAX_MSG, P4TC_PIPELINE_NUMTABLES,
					  numtables);
			} else if (strcmp(*argv, "state") == 0
				   && cmd == RTM_UPDATEP4TEMPLATE) {
				argv++;
				argc--;
				if (strcmp(*argv, "ready") == 0) {
					addattr8(n, MAX_MSG,
						 P4TC_PIPELINE_STATE,
						 P4TC_STATE_NOT_READY);
				}
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
			argv++;
			argc--;
		}
		addattr_nest_end(n, nest);
	} else {
		while (argc > 0) {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
			argv++;
			argc--;
		}
	}

	if (cmd == RTM_CREATEP4TEMPLATE || cmd == RTM_UPDATEP4TEMPLATE)
		addattr_nest_end(n, nest);

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

int p4tc_pipeline_get_id(const char *pname, __u32 *pipeid)
{
	struct nlmsghdr *ans;
	struct rtattr *root;
	struct p4tcmsg *t;
	struct {
		struct nlmsghdr		n;
		struct p4tcmsg		t;
		char			buf[MAX_MSG];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct p4tcmsg)),
		.n.nlmsg_type = RTM_GETP4TEMPLATE,
	};
	int ret;

	req.t.obj = P4TC_OBJ_PIPELINE;

	addattrstrz(&req.n, MAX_MSG, P4TC_ROOT_PNAME, pname);
	root = addattr_nest(&req.n, MAX_MSG, P4TC_ROOT | NLA_F_NESTED);

	req.n.nlmsg_flags = NLM_F_REQUEST,
	addattr_nest_end(&req.n, root);
	ret = rtnl_talk(&rth, &req.n, &ans);
	if (ret < 0) {
		fprintf(stderr,
			"Unable to get pipeline ID from kernel\n");
		return -1;
	}

	t = NLMSG_DATA(ans);

	*pipeid = t->pipeid;
	return 0;
}

static int p4tmpl_cmd(int cmd, unsigned int flags, int *argc_p,
		      char ***argv_p)
{
	char *p4tcpath[MAX_PATH_COMPONENTS] = {};
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret = 0;
	struct rtattr *root;
	int obj_type;
	char *pname;
	int pipeid;

	struct {
		struct nlmsghdr		n;
		struct p4tcmsg		t;
		char			buf[MAX_MSG];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct p4tcmsg)),
		.n.nlmsg_type = cmd,
	};

	argc -= 1;
	argv += 1;

	if (!argc) {
		p4template_usage();
		return -1;
	}

	parse_path(*argv, p4tcpath, "/");
	if (!p4tcpath[PATH_OBJ_IDX]) {
		fprintf(stderr, "Invalid path %s\n", *argv);
		return -1;
	}

	obj_type = get_obj_type(p4tcpath[PATH_OBJ_IDX]);
	if (obj_type < 0) {
		fprintf(stderr, "Can't process unknown object type: %s\n",
			p4tcpath[PATH_OBJ_IDX]);
		return -1;
	}

	req.t.obj = obj_type;

	argc -= 1;
	argv += 1;

	pname = p4tcpath[PATH_PNAME_IDX];
	if (pname)
		addattrstrz(&req.n, MAX_MSG, P4TC_ROOT_PNAME, pname);
	root = addattr_nest(&req.n, MAX_MSG, P4TC_ROOT | NLA_F_NESTED);

	switch (obj_type) {
	case P4TC_OBJ_PIPELINE:
		pipeid = parse_pipeline_data(&argc, &argv, &req.n, cmd, flags);
		if (pipeid < 0)
			return -1;
		req.t.pipeid = pipeid;

		if (!pipeid && !pname)
			flags |= NLM_F_ROOT;

		break;
	case P4TC_OBJ_TABLE:
		pipeid = parse_table_data(&argc, &argv, &req.n, p4tcpath, cmd,
					  &flags);
		if (pipeid < 0)
			return -1;
		req.t.pipeid = pipeid;

		break;
	case P4TC_OBJ_ACT:
		pipeid = parse_action_data(&argc, &argv, &req.n, p4tcpath, cmd,
					&flags);
		if (pipeid < 0)
			return -1;
		req.t.pipeid = pipeid;

		break;
	case P4TC_OBJ_EXT:
		ret = parse_extern_data(&argc, &argv, &req.n, p4tcpath, cmd,
					&flags);
		if (ret < 0)
			return -1;
		req.t.pipeid = 0;
		break;
	case P4TC_OBJ_EXT_INST:
		ret = parse_extern_inst_data(&argc, &argv, &req.n, p4tcpath,
					     cmd, &flags);
		if (ret < 0)
			return -1;
		req.t.pipeid = ret;
		break;
	default:
		fprintf(stderr, "Unknown template object type %s\n",
			p4tcpath[PATH_PNAME_IDX]);
		return -1;
	}
	req.n.nlmsg_flags = NLM_F_REQUEST | flags,
	addattr_nest_end(&req.n, root);

	if (cmd == RTM_GETP4TEMPLATE) {
		if (flags & NLM_F_ROOT) {
			int msg_size;

			msg_size = NLMSG_ALIGN(req.n.nlmsg_len) -
				NLMSG_ALIGN(sizeof(struct nlmsghdr));
			if (rtnl_dump_request(&rth, RTM_GETP4TEMPLATE,
					      (void *)&req.t, msg_size) < 0) {
				perror("Cannot send dump request");
				return -1;
			}

			new_json_obj(json);
			if (rtnl_dump_filter(&rth, print_p4tmpl, stdout) < 0) {
				fprintf(stderr, "Dump terminated\n");
				return -1;
			}
			delete_json_obj();
		} else {
			struct nlmsghdr *ans = NULL;

			if (rtnl_talk(&rth, &req.n, &ans) < 0) {
				fprintf(stderr,
					"We have an error talking to the kernel\n");
				return -1;
			}

			new_json_obj(json);
			print_p4tmpl(ans, stdout);
			delete_json_obj();
		}
	} else {
		if (echo_request)
			ret = rtnl_echo_talk(&rth, &req.n, json,
					     print_p4tmpl);
		else
			ret = rtnl_talk(&rth, &req.n, NULL);

		if (ret < 0) {
			fprintf(stderr,
				"We have an error talking to the kernel\n");
			return -1;
		}
	}

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

int do_p4tmpl(int argc, char **argv)
{
	int ret = 0;

	while (argc > 0) {
		if (matches(*argv, "create") == 0) {
			ret = p4tmpl_cmd(RTM_CREATEP4TEMPLATE,
					 NLM_F_EXCL | NLM_F_CREATE, &argc,
					 &argv);
		} else if (matches(*argv, "update") == 0) {
			ret = p4tmpl_cmd(RTM_UPDATEP4TEMPLATE, 0, &argc, &argv);
		} else if (matches(*argv, "delete") == 0) {
			ret = p4tmpl_cmd(RTM_DELP4TEMPLATE, 0, &argc, &argv);
		} else if (matches(*argv, "get") == 0) {
			ret = p4tmpl_cmd(RTM_GETP4TEMPLATE, 0, &argc, &argv);
		} else if (matches(*argv, "help") == 0) {
			p4template_usage();
			ret = -1;
		} else {
			fprintf(stderr,
				"Command \"%s\" is unknown, try \"tc p4template help\".\n",
				*argv);
			return -1;
		}

		if (ret < 0)
			return -1;
	}

	return 0;
}
