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
	}

	if (tb[P4TC_ROOT_PNAME]) {
		char *pname = RTA_DATA(tb[P4TC_ROOT_PNAME]);

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
	char full_tblname[P4TC_TABLE_NAMSIZ] = {0};
	bool parsed_permissions = false;
	char *pname, *cbname, *tblname;
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
