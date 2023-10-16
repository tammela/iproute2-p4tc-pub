/*
 * p4_tc_table.c		P4 TC Table Management
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
#include <dirent.h>
#include <sys/stat.h>

#include "utils.h"
#include "rt_names.h"
#include "tc_common.h"
#include "tc_util.h"
#include "names.h"
#include "p4tc_common.h"
#include "p4_types.h"
#include "p4tc_filter.h"

static void parse_common(__u8 *keyblob, __u8 *maskblob,
			 struct p4_type_value *val, __u32 *offset, size_t sz)
{
	memcpy((keyblob + *offset), val->value, sz);
	memcpy((maskblob + *offset), val->mask, sz);
	*offset += sz;
}

static void print_entry_tm(const char *prefix, FILE *f,
			   const struct p4tc_table_entry_tm *tm)
{
	int hz = get_user_hz();

	if (tm->created != 0) {
		print_string(PRINT_FP, NULL, "%s", prefix);
		print_uint(PRINT_ANY, "created", "    created %u sec",
			   tm->created / hz);
	}

	if (tm->lastused != 0) {
		print_string(PRINT_FP, NULL, "%s", prefix);
		print_uint(PRINT_ANY, "last_used", "    used %u sec",
			   tm->lastused / hz);
	}

	if (tm->firstused != 0) {
		print_string(PRINT_FP, NULL, "%s", prefix);
		print_uint(PRINT_ANY, "first_used", "    firstused %u sec",
			   tm->firstused / hz);
	}
	print_nl();
}

int print_table_entry(struct nlmsghdr *n, struct rtattr *arg, FILE *f,
		      const char *prefix, struct p4tc_json_table *table,
		      __u32 tbl_id)
{
	struct rtattr *tb[P4TC_ENTRY_MAX + 1];
	unsigned int len;

	parse_rtattr_nested(tb, P4TC_ENTRY_MAX, arg);

	if (table) {
		print_string(PRINT_ANY, "tblname", " table: %s", table->name);
		print_uint(PRINT_ANY, "tblid", "(id %u)", table->id);
	} else {
		if (tbl_id)
			print_uint(PRINT_ANY, "tblid", " table: \?\?(id %u)\n",
				   tbl_id);
		else
			print_uint(PRINT_ANY, "tblid",
				   " table: \?\?\?(id %u)\n", tbl_id);
	}

	if (tb[P4TC_ENTRY_PRIO]) {
		__u32 *prio = RTA_DATA(tb[P4TC_ENTRY_PRIO]);

		print_string(PRINT_FP, NULL, "%s", prefix);
		print_uint(PRINT_ANY, "prio", "entry priority %u", *prio);
	}

	if (tb[P4TC_ENTRY_PERMISSIONS]) {
		__u16 *permissions;

		permissions = RTA_DATA(tb[P4TC_ENTRY_PERMISSIONS]);
		p4tc_print_permissions("[", permissions, "]\n", f);
	}

	if (!tb[P4TC_ENTRY_KEY_BLOB] || !tb[P4TC_ENTRY_MASK_BLOB]) {
		fprintf(stderr, "Must specify key and mask blobs");
		return -1;
	}

	len = RTA_PAYLOAD(tb[P4TC_ENTRY_KEY_BLOB]);
	if (len != RTA_PAYLOAD(tb[P4TC_ENTRY_MASK_BLOB]) ||
	    (table && len*8 != table->ksize)) {
		if (table)
			fprintf(stderr,
				"Size mismatch: table %db key %dB mask %ldB",
				table->ksize, len,
				RTA_PAYLOAD(tb[P4TC_ENTRY_MASK_BLOB]));
		else
			fprintf(stderr, "Size mismatch: key %dB mask %ldB", len,
				RTA_PAYLOAD(tb[P4TC_ENTRY_MASK_BLOB]));
		return -1;
	}

	if (table) {
		__u8 mask[P4TC_MAX_KEYSZ >> 3] = {0};
		__u8 key[P4TC_MAX_KEYSZ >> 3] = {0};

		memcpy(key, RTA_DATA(tb[P4TC_ENTRY_KEY_BLOB]), len);
		memcpy(mask, RTA_DATA(tb[P4TC_ENTRY_MASK_BLOB]), len);
		p4tc_json_print_key_data(table, key, mask, len, f, prefix);
	}

	if (tb[P4TC_ENTRY_ACT]) {
		print_string(PRINT_FP, NULL,
			     "%s    entry actions:", prefix);
		open_json_object("actions");
		tc_print_action(f, tb[P4TC_ENTRY_ACT], 0);
		print_nl();
		close_json_object();
	}

	if (!tb[P4TC_ENTRY_KEY_BLOB] || !tb[P4TC_ENTRY_MASK_BLOB]) {
		fprintf(stderr, "Bad table entry, missing key and mask");
		return -1;
	}


	len = RTA_PAYLOAD(tb[P4TC_ENTRY_KEY_BLOB]);
	if (len != RTA_PAYLOAD(tb[P4TC_ENTRY_MASK_BLOB])) {
		fprintf(stderr, "Key and mask blob's sizes must match");
		return -1;
	}

	if (tb[P4TC_ENTRY_CREATE_WHODUNNIT]) {
		__u8 *whodunnit = RTA_DATA(tb[P4TC_ENTRY_CREATE_WHODUNNIT]);
		char name[NAME_MAX_LEN];
		int ret;

		ret = p4tc_ctrltable_getbyid(*whodunnit, name);
		if (!ret) {
			print_string(PRINT_ANY, "create_whodunnit",
				     "    created by: %s ", name);
			print_int(PRINT_ANY, "create_whodunnit_id",
				     "(id %d)\n", *whodunnit);
		} else {
			print_string(PRINT_ANY, "create_whodunnit",
				     "    created by: %s ", "\?\?");
			print_int(PRINT_ANY, "create_whodunnit_id",
				     "(id %d)\n", *whodunnit);
		}

	}

	if (tb[P4TC_ENTRY_UPDATE_WHODUNNIT]) {
		__u8 *whodunnit = RTA_DATA(tb[P4TC_ENTRY_UPDATE_WHODUNNIT]);
		char name[NAME_MAX_LEN];
		int ret;

		ret = p4tc_ctrltable_getbyid(*whodunnit, name);
		if (!ret) {
			print_string(PRINT_ANY, "update_whodunnit",
				     "    updated by: %s ", name);
			print_int(PRINT_ANY, "update_whodunnit_id",
				     "(id %d)\n", *whodunnit);
		} else {
			print_string(PRINT_ANY, "update_whodunnit",
				     "    updated by: %s ", "\?\?");
			print_int(PRINT_ANY, "update_whodunnit_id",
				     "(id %d)\n", *whodunnit);
		}
	}

	if (tb[P4TC_ENTRY_DELETE_WHODUNNIT]) {
		__u8 *whodunnit = RTA_DATA(tb[P4TC_ENTRY_DELETE_WHODUNNIT]);
		char name[NAME_MAX_LEN];
		int ret;

		ret = p4tc_ctrltable_getbyid(*whodunnit, name);
		if (!ret) {
			print_string(PRINT_ANY, "delete_whodunnit",
				     "    deleted by: %s ", name);
			print_int(PRINT_ANY, "delete_whodunnit_id",
				     "(id %d)\n", *whodunnit);
		} else {
			print_string(PRINT_ANY, "delete_whodunnit",
				     "    deleted by: %s ", "\?\?");
			print_int(PRINT_ANY, "delete_whodunnit_id",
				     "(id %d)\n", *whodunnit);
		}
	}

	if (tb[P4TC_ENTRY_DYNAMIC])
		print_string(PRINT_ANY, "dynamic", "    dynamic %s\n",
			   "true");
	else
		print_string(PRINT_ANY, "dynamic", "    dynamic %s\n",
			   "false");

	if (tb[P4TC_ENTRY_AGING]) {
		__u64 *aging = RTA_DATA(tb[P4TC_ENTRY_AGING]);

		print_uint(PRINT_ANY, "aging", "    table aging %u\n", *aging);
	}

	if (tb[P4TC_ENTRY_TM]) {
		struct p4tc_table_entry_tm *tm;

		tm = RTA_DATA(tb[P4TC_ENTRY_TM]);
		print_entry_tm(prefix, f, tm);
	}

	if (tb[P4TC_ENTRY_TMPL_CREATED])
		print_string(PRINT_ANY, "tmpl_created", "    tmpl created %s\n",
			   "true");
	else
		print_string(PRINT_ANY, "tmpl_created", "    tmpl created %s\n",
			   "false");

	if (tb[P4TC_ENTRY_COUNTER])
		p4tc_print_one_extern(f, tb[P4TC_ENTRY_COUNTER], false);

	print_nl();

	return 0;
}

static int print_table_entry_flush(struct nlmsghdr *n,  struct rtattr *cnt_attr,
				   FILE *f)
{
	const __u32 *cnt = RTA_DATA(cnt_attr);

	print_uint(PRINT_ANY, "tecount", "    table entry flush count %u",
		   *cnt);
	print_nl();

	return 0;
}

static int print_table_1(struct nlmsghdr *n, struct p4tc_json_pipeline *pipe,
			 struct rtattr *arg, FILE *f)
{
	struct p4tc_json_table *table = NULL;
	struct rtattr *tb[P4TC_MAX + 1];
	int cmd = n->nlmsg_type;
	__u32 *tbl_id = NULL;

	parse_rtattr_nested(tb, P4TC_MAX, arg);

	if (tb[P4TC_PATH])
		tbl_id = RTA_DATA(tb[P4TC_PATH]);

	if (tbl_id) {
		if (pipe) {
			table = p4tc_json_find_table_byid(pipe, *tbl_id);
			if (!table) {
				fprintf(stderr, "Unable to find table id %d\n",
					*tbl_id);
				return -1;
			}
		}
	}

	if (cmd == RTM_P4TC_DEL && (n->nlmsg_flags & NLM_F_ROOT))
		print_table_entry_flush(n, tb[P4TC_COUNT], f);
	else {
		if (tb[P4TC_PARAMS])
			print_table_entry(n, tb[P4TC_PARAMS], f, "", table,
					  tbl_id ? *tbl_id : 0);
	}

	return 0;
}

static int print_table_root(struct nlmsghdr *n, struct p4tc_json_pipeline *pipe,
			    struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, arg);

	open_json_array(PRINT_JSON, "entries");
	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		open_json_object(NULL);
		print_table_1(n, pipe, tb[i], f);
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);

	return 0;
}

int print_table(struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1] = {};
	struct p4tc_json_pipeline *pipe = NULL;
	struct p4tcmsg *t = NLMSG_DATA(n);
	__u32 flags = n->nlmsg_flags;
	int len;

	open_json_object(NULL);
	switch (n->nlmsg_type) {
	case RTM_P4TC_CREATE:
		print_bool(PRINT_ANY, "created", "created ",
			   true);
		break;
	case RTM_P4TC_UPDATE:
		print_bool(PRINT_ANY, "updated", "updated ",
			   true);
		break;
	case RTM_P4TC_DEL:
		if (flags & NLM_F_ROOT)
			print_bool(PRINT_ANY, "flushed", "flushed ", true);
		else
			print_bool(PRINT_ANY, "deleted", "deleted ", true);
		break;
	default:
		break;
	}

	len = n->nlmsg_len;
	len -= NLMSG_LENGTH(sizeof(*t));

	parse_rtattr_flags(tb, P4TC_ROOT_MAX, P4TC_RTA(t), len, NLA_F_NESTED);

	if (tb[P4TC_ROOT_PNAME]) {
		char *pname = RTA_DATA(tb[P4TC_ROOT_PNAME]);

		pipe = p4tc_json_import(pname);
		if (!pipe) {
			fprintf(stderr, "Unable to find pipeline %s\n",
				pname);
			print_string(PRINT_ANY, "pname", "pipeline: %s",
				     pname);
			if (t->pipeid)
				print_uint(PRINT_ANY, "pipeid", "(id %u)",
					   t->pipeid);
		} else {
			pipe->id = t->pipeid;
			print_string(PRINT_ANY, "pname", "pipeline:  %s",
				     pipe->name);
			print_uint(PRINT_ANY, "pipeid", "(id %u)",
				   t->pipeid);
		}
		print_nl();
	}
	close_json_object();

	if (tb[P4TC_ROOT]) {
		open_json_object(NULL);
		print_table_root(n, pipe, tb[P4TC_ROOT], (FILE *)arg);
		close_json_object();
	}

	if (pipe)
		p4tc_json_free_pipeline(pipe);

	return 0;
}

static int __parse_table_keys(struct parse_state *state, __u32 *offset,
			      const char *argv, __u32 bitsz,
			      struct p4_type_s *type)
{
	int bytesz = (bitsz % 8) ? bitsz / 8 + 1 : bitsz / 8;
	__u8 *mask = calloc(1, bytesz);
	__u8 *value = calloc(1, bytesz);
	struct p4_type_value val;

	if (!value) {
		fprintf(stderr, "Unable to alloc value");
		return -1;
	}

	if (!mask) {
		fprintf(stderr, "Unable to alloc mask");
		free(value);
		return -1;
	}

	if (!type->parse_p4t) {
		fprintf(stderr, "Type has no parse function\n");
		free(value);
		free(mask);
		return -1;
	}

	val.value = value;
	val.mask = mask;
	val.bitsz = bitsz ? bitsz : type->bitsz;
	if (type->parse_p4t(&val, argv, 0) < 0) {
		fprintf(stderr, "Failed to parse %s\n", argv);
		free(value);
		free(mask);
		return -1;
	}

	if (!(type->flags & P4TC_T_TYPE_HAS_MASK)) {
		int i;

		for (i = 0; i < bytesz; i++)
			mask[i] = 0xFF;
	}

	parse_common(state->keyblob, state->maskblob, &val, offset,
		     bytesz);

	free(value);
	free(mask);

	return 0;
}

static void print_table_entry_help_key(struct p4tc_json_key_fields_list *key)
{

	fprintf(stderr, "\t key name %s\n", key->name);
	fprintf(stderr, "\t key id %u\n", key->id);
	fprintf(stderr, "\t key type %s\n", key->type);

	fprintf(stderr, "\t key match type ");
	switch (key->match_type) {
	case P4TC_MATCH_TYPE_EXACT:
		fprintf(stderr, "\t exact");
		break;
	case P4TC_MATCH_TYPE_LPM:
		fprintf(stderr, "\t lpm");
		break;
	case P4TC_MATCH_TYPE_TERNARY:
		fprintf(stderr, "\t ternary");
		break;
	default:
		break;
	}

	fprintf(stderr, "\n");
}

static void print_table_entry_help_keys(struct p4tc_json_table *t)
{

	struct p4tc_json_key_fields_list *key;

	key = p4tc_json_table_keyfield_iter_start(t);
	while (key) {
		print_table_entry_help_key(key);
		key = p4tc_json_table_keyfield_next(key);
	}
}

static void print_table_entry_help_act_param(struct p4tc_json_action_data *param)
{

	fprintf(stderr, "\t    param name %s\n", param->name);
	fprintf(stderr, "\t    param id %u\n", param->id);
	fprintf(stderr, "\t    param type %s\n", param->type);

	print_nl();
}

static void print_table_entry_help_acts_params(struct p4tc_json_actions_list *act)
{
	struct p4tc_json_action_data *param;

	param = p4tc_json_action_data_start_iter(act);
	if (!param)
		return;

	fprintf(stderr, "\t  Params for %s:\n", act->name);
	while (param) {
		print_table_entry_help_act_param(param);
		param = p4tc_json_action_data_next(param);
	}
}

static void print_table_entry_help_act(struct p4tc_json_actions_list *act)
{

	fprintf(stderr, "\t  act name %s\n", act->name);
	fprintf(stderr, "\t  act id %u\n", act->id);
	print_nl();

	print_table_entry_help_acts_params(act);

	print_nl();
}

static void print_table_entry_help_acts(struct p4tc_json_table *t)
{

	struct p4tc_json_actions_list *act;

	act = p4tc_json_table_action_iter_start(t);
	while (act) {
		print_table_entry_help_act(act);
		act = p4tc_json_action_next(act);
	}
}

static void print_table_entry_help_tbl(struct p4tc_json_table *t)
{
	fprintf(stderr, "\t  table name %s\n", t->name);
	fprintf(stderr, "\t  table id %u\n", t->id);
	print_nl();
}

static void print_table_entry_help_tbls(struct p4tc_json_pipeline *p)
{
	struct p4tc_json_table_list *tbl_list;

	print_nl();
	fprintf(stderr, "Tables for pipeline %s:\n", p->name);

	tbl_list = p4tc_json_table_iter_start(p);
	while (tbl_list) {
		print_table_entry_help_tbl(&tbl_list->table);
		tbl_list = p4tc_json_table_next(tbl_list);
	}
}

int parse_table_entry_help(int cmd, char **p4tcpath)
{
	const char *tblname = p4tcpath[PATH_TBLNAME_IDX];
	const char *cbname = p4tcpath[PATH_CBNAME_IDX];
	char full_tblname[P4TC_TABLE_NAMSIZ] = {0};
	struct p4tc_json_pipeline *p;
	struct p4tc_json_table *t;
	int ret = 0;
	char *pname;

	pname = p4tcpath[PATH_TABLE_PNAME_IDX];

	p = p4tc_json_import(pname);
	if (!p) {
		fprintf(stderr, "parse keys - Unable to find pipeline %s\n",
			p4tcpath[PATH_TABLE_PNAME_IDX]);
		return -1;
	}

	if (!tblname) {
		print_table_entry_help_tbls(p);
		ret = -1;
		goto free_json_pipeline;
	}

	if (concat_cb_name(full_tblname, cbname, tblname, P4TC_TABLE_NAMSIZ) < 0) {
		fprintf(stderr, "Table name to long %s/%s\n", cbname, tblname);
		ret = -1;
		goto free_json_pipeline;
	}

	t = p4tc_json_find_table(p, full_tblname);
	if (!t) {
		fprintf(stderr, "Unable to find table %s\n", tblname);
		goto free_json_pipeline;
	}

	if (cmd == RTM_P4TC_CREATE || cmd == RTM_P4TC_UPDATE) {
		if (cmd == RTM_P4TC_CREATE && t->permissions &&
		    !p4tc_ctrl_create_ok(t->permissions)) {
			fprintf(stderr,
				"Table doesn't have control create permissions\n");
			ret = -1;
			goto free_json_pipeline;
		} else if (cmd == RTM_P4TC_UPDATE && t->permissions &&
			   !p4tc_ctrl_update_ok(t->permissions)) {
			fprintf(stderr,
				"Table doesn't have control update permissions\n");
			ret = -1;
			goto free_json_pipeline;
		}

		fprintf(stderr, "Key fields for table %s:\n", tblname);
		print_table_entry_help_keys(t);

		print_nl();
		fprintf(stderr, "Actions for table %s:\n", tblname);
		print_table_entry_help_acts(t);
	} else {
		if (cmd == RTM_P4TC_GET && t->permissions &&
		    !p4tc_ctrl_read_ok(t->permissions)) {
			fprintf(stderr,
				"Table doesn't have control read permissions\n");
			ret = -1;
			goto free_json_pipeline;
		} else if (cmd == RTM_P4TC_DEL && t->permissions &&
			   !p4tc_ctrl_delete_ok(t->permissions)) {
			fprintf(stderr,
				"Table doesn't have control delete permissions\n");
			ret = -1;
			goto free_json_pipeline;
		}

		fprintf(stderr, "Key fields for table %s:\n", tblname);
		print_table_entry_help_keys(t);
	}

free_json_pipeline:
	p4tc_json_free_pipeline(p);

	return ret;
}

struct p4tc_json_key_fields_list *
introspect_key_field_byname(struct p4tc_json_pipeline **p,
			     struct p4tc_json_table **t, const char *pname,
			     const char **p4tcpath, const char *keyname)
{
	const char *tblname = p4tcpath[PATH_TBLNAME_IDX];
	const char *cbname = p4tcpath[PATH_CBNAME_IDX];
	struct p4tc_json_key_fields_list *key = NULL;
	char full_tblname[P4TC_TABLE_NAMSIZ] = {0};

	*p = p4tc_json_import(pname);
	if (!(*p)) {
		fprintf(stderr, "parse keys - Unable to find pipeline %s\n",
			p4tcpath[PATH_TABLE_PNAME_IDX]);
		return NULL;
	}

	if (concat_cb_name(full_tblname, cbname, tblname, P4TC_TABLE_NAMSIZ) < 0) {
		fprintf(stderr, "Table name to long %s/%s\n", cbname, tblname);
		goto free_json_pipeline;
	}

	*t = p4tc_json_find_table(*p, full_tblname);
	if (!(*t)) {
		fprintf(stderr, "Unable to find table %s\n", tblname);
		goto free_json_pipeline;
	}

	key = p4tc_json_find_table_keyfield(*t, 1, keyname);
	if (!key) {
		fprintf(stderr,
			"Unable to find key field %s in introspection file\n",
			keyname);
		goto free_json_pipeline;
	}

	return key;

free_json_pipeline:
	p4tc_json_free_pipeline(*p);
	return key;
}

static int parse_table_keys(int *argc_p, char ***argv_p,
			    struct parse_state *state, __u32 *offset,
			    char **p4tcpath, const char *pname, __u32 tbl_id)
{
	struct p4tc_json_key_fields_list *key;
	struct p4tc_json_pipeline *p;
	struct p4tc_json_table *t;
	char **argv = *argv_p;
	struct p4_type_s *typ;
	int argc = *argc_p;
	int ret = 0;
	__u32 bitsz;

	key = introspect_key_field_byname(&p, &t, pname,
					  (const char **)p4tcpath, *argv);
	if (!key)
		return -1;

	state->has_parsed_keys = true;
	typ = get_p4type_byarg(key->type, &bitsz);
	if (!typ) {
		fprintf(stderr, "Unable to find type %s\n", key->type);
		ret = -1;
		goto free_json_pipeline;
	}
	if (key) {
		NEXT_ARG();
		if (__parse_table_keys(state, offset, *argv,
				       bitsz, typ) < 0) {
			ret = -1;
		}
	} else {
		fprintf(stderr, "Unknown arg %s\n", *argv);
		ret = -1;
	}

free_json_pipeline:
	p4tc_json_free_pipeline(p);

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

/* We assume that a table action name containing "/" refers to a separate table
 * action or a pipeline action. This means we treat action name as an absolute
 * path.
 */
static bool is_relative_path(const char *act_name)
{
	char *act_name_copy = strdupa(act_name);

	return strchr(act_name_copy, '/') == NULL;
}

static int parse_table_name(const char **p4tcpath, char *full_tblname)
{
	const char *cbname, *tblname;
	int ret;

	cbname = p4tcpath[PATH_CBNAME_IDX];
	tblname = p4tcpath[PATH_TBLNAME_IDX];

	if (cbname && tblname) {
		ret = concat_cb_name(full_tblname, cbname, tblname,
				     P4TC_TABLE_NAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "table name too long\n");
			return -1;
		}
	}

	return 0;
}

static int __parse_table_action(int *argc_p, char ***argv_p, char **p4tcpath,
				char actname[], const char *pname,
				struct nlmsghdr *n, __u32 nla_param_attr)
{
	char full_tblname[P4TC_TABLE_NAMSIZ];
	bool introspect_global = false;
	char full_actname[ACTNAMSIZ];
	char **argv = *argv_p;
	struct rtattr *tail;
	const char *cbname;
	int argc = *argc_p;
	int ret;

	cbname = p4tcpath[PATH_CBNAME_IDX];

	if (is_relative_path(actname)) {
		snprintf(full_actname, ACTNAMSIZ, "%s/%s/%s", pname, cbname,
			 actname);
		strlcpy(actname, full_actname, ACTNAMSIZ);
		introspect_global = true;
	}

	ret = parse_table_name((const char **)p4tcpath, full_tblname);
	if (ret < 0)
		return ret;

	NEXT_ARG_FWD();
	if (nla_param_attr)
		tail = addattr_nest(n, MAX_MSG, nla_param_attr | NLA_F_NESTED);
	ret = parse_dyna_tbl_act(&argc, &argv, &actname, full_tblname,
				 introspect_global, n, !!nla_param_attr);
	if (nla_param_attr)
		addattr_nest_end(n, tail);
	if (ret < 0) {
		fprintf(stderr, "bad action parsing\n");
		return -1;
	}

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

/* This function allows for the binding of many actions to a table entry.
 * We are aware P4 doesn't allow for this, but we are making an exception since
 * something of this sort is perfectly legal and reasonable for TC.
 */
static int parse_table_action(int *argc_p, char ***argv_p, char **p4tcpath,
			      const char *pname, struct nlmsghdr *n)
{
	struct rtattr *tail, *tail2, *tail3;
	char **argv = *argv_p;
	int argc = *argc_p;
	int prio = 0;
	int ret = 0;
	int eap = 0;

	tail2 = addattr_nest(n, MAX_MSG, P4TC_ENTRY_ACT | NLA_F_NESTED);

	while (argc > 0) {
		if (strcmp(*argv, "action") == 0) {
			argc--;
			argv++;
			eap = 1;
		} else if (strcmp(*argv, "entry") == 0) {
			break;
		} else {
			char actname[ACTNAMSIZ] = {};
			__u32 flag = 0;

			strlcpy(actname, *argv, ACTNAMSIZ);

			eap = 0;

			tail = addattr_nest(n, MAX_MSG, ++prio);
			tail3 = addattr_nest(n, MAX_MSG,
					     TCA_ACT_OPTIONS | NLA_F_NESTED);
			ret = __parse_table_action(&argc, &argv, p4tcpath,
						   actname, pname, n, 0);
			if (ret < 0) {
				fprintf(stderr, "bad action parsing\n");
				goto bad_val;
			}
			addattr_nest_end(n, tail3);

			addattrstrz(n, MAX_MSG, TCA_ACT_KIND, actname);

			if (*argv && strcmp(*argv, "skip_sw") == 0) {
				flag |= TCA_ACT_FLAGS_SKIP_SW;
				NEXT_ARG_FWD();
			} else if (*argv && strcmp(*argv, "skip_hw") == 0) {
				flag |= TCA_ACT_FLAGS_SKIP_HW;
				NEXT_ARG_FWD();
			}

			if (flag) {
				struct nla_bitfield32 flags = { flag, flag };

				addattr_l(n, MAX_MSG, TCA_ACT_FLAGS, &flags,
					  sizeof(struct nla_bitfield32));
			}
			addattr_nest_end(n, tail);
		}
	}

	if (eap > 0) {
		fprintf(stderr, "table action empty %d\n", eap);
		goto bad_val;
	}

	addattr_nest_end(n, tail2);

	*argc_p = argc;
	*argv_p = argv;
	return 0;

bad_val:
	fprintf(stderr, "%s: bad value (%d:%s)!\n", __func__, argc,
		*argv);
	return -1;
}

static int parse_table_profile(int *argc_p, char ***argv_p, struct nlmsghdr *n)
{
	char **argv = *argv_p;
	struct rtattr *tail;
	int argc = *argc_p;

	tail = addattr_nest(n, MAX_MSG,
			    P4TC_ENTRY_TBL_ATTRS_TIMER_PROFILE | NLA_F_NESTED);

	while (argc > 0) {
		if (strcmp(*argv, "id") == 0) {
			__u32 profile_id;

			NEXT_ARG();
			if (get_u32(&profile_id, *argv, 0) < 0)
				return -1;
			addattr32(n, MAX_MSG, P4TC_TIMER_PROFILE_ID,
				  profile_id);
			NEXT_ARG_FWD();
		} else if (strcmp(*argv, "aging") == 0) {
			__u64 profile_aging;

			NEXT_ARG();
			if (get_u64(&profile_aging, *argv, 0) < 0)
				return -1;
			addattr64(n, MAX_MSG, P4TC_TIMER_PROFILE_AGING,
				  profile_aging);
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

static int parse_table_attrs(int *argc_p, char ***argv_p, struct nlmsghdr *n)
{
	char **argv = *argv_p;
	struct rtattr *parm;
	int argc = *argc_p;

	parm = addattr_nest(n, MAX_MSG, P4TC_ENTRY_TBL_ATTRS | NLA_F_NESTED);

	while (argc > 0) {
		if (strcmp(*argv, "default_hit_action") == 0) {
			int def_hit_attrs = P4TC_ENTRY_TBL_ATTRS_DEFAULT_HIT;

			NEXT_ARG();
			if (parse_table_default_action(&argc, &argv, n,
						       def_hit_attrs))
				return -1;
		} else if (strcmp(*argv, "default_miss_action") == 0) {
			int def_miss_attrs = P4TC_ENTRY_TBL_ATTRS_DEFAULT_MISS;

			NEXT_ARG();
			if (parse_table_default_action(&argc, &argv, n,
						       def_miss_attrs))
				return -1;
		} else if (strcmp(*argv, "tbl_permissions") == 0) {
			__u16 permissions;

			NEXT_ARG();
			if (get_u16(&permissions, *argv, 16) < 0)
				return -1;

			addattr16(n, MAX_MSG, P4TC_ENTRY_TBL_ATTRS_PERMISSIONS,
				  permissions);
		} else if (strcmp(*argv, "timer_profile") == 0) {
			NEXT_ARG();
			if (parse_table_profile(&argc, &argv, n) < 0)
				return -1;
		} else {
			break;
		}
		argv++;
		argc--;
	}

	addattr_nest_end(n, parm);

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

int parse_new_table_entry(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			  struct parse_state *state, char *p4tcpath[],
			  const char *pname, __u32 *ids, __u32 *offset)
{
	struct p4tc_arch_json *arch_info = NULL;
	__u32 pipeid = 0, tbl_id = 0, prio = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 permissions;
	int ret;

	while (argc > 0) {
		if (strcmp(*argv, "prio") == 0) {
			__u32 prio;

			NEXT_ARG();
			if (get_u32(&prio, *argv, 10)) {
				fprintf(stderr, "Invalid prio\n");
				return -1;
			}
			addattr32(n, MAX_MSG, P4TC_ENTRY_PRIO, prio);
		} else if (strcmp(*argv, "action") == 0) {
			if (parse_table_action(&argc, &argv, p4tcpath, pname,
					       n)) {
				fprintf(stderr, "Illegal action\n");
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "permissions") == 0) {
			NEXT_ARG();
			if (get_u16((__u16*)&permissions, *argv, 16) < 0)
				return -1;

			addattr16(n, MAX_MSG, P4TC_ENTRY_PERMISSIONS,
				  (__u16)permissions);
		} else if (strcmp(*argv, "tbl_attrs") == 0) {
			NEXT_ARG();
			if (parse_table_attrs(&argc, &argv, n))
				return -1;
		} else if (strcmp(*argv, "dynamic") == 0) {
			__u8 is_dynamic = 1;

			addattr8(n, MAX_MSG, P4TC_ENTRY_DYNAMIC, is_dynamic);
		} else if (strcmp(*argv, "aging") == 0) {
			struct p4tc_json_profile *profile;
			__u64 aging;

			NEXT_ARG();
			if (get_u64(&aging, *argv, 0) < 0)
				return -1;
			if (arch_info) {
				profile = p4tc_json_find_profile_by_aging
					(arch_info, aging);
				if (!profile) {
					fprintf(stderr,
						"Unable to find profile\n");
					return -1;
				}
			}
			addattr64(n, MAX_MSG, P4TC_ENTRY_AGING, aging);
		} else if (strcmp(*argv, "profile_id") == 0) {
			__u32 profile_id;

			NEXT_ARG();
			if (get_u32(&profile_id, *argv, 0))
				return -1;

			addattr32(n, MAX_MSG, P4TC_ENTRY_PROFILE_ID,
				  profile_id);
		} else if (strcmp(*argv, "arch_file") == 0) {
			NEXT_ARG();
			arch_info = p4tc_json_import_arch(*argv);
			if (!arch_info)
				return -1;
		} else if (strcmp(*argv, "entry") == 0) {
			goto out;
		} else {
			ret = parse_table_keys(&argc, &argv, state,
					       offset, p4tcpath, pname, tbl_id);
			if (ret < 0)
				return -1;

		}

		argv++;
		argc--;
	}

out:
	addattr8(n, MAX_MSG, P4TC_ENTRY_WHODUNNIT, P4TC_ENTITY_TC);
	ids[0] = tbl_id;
	ids[1] = prio;
	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

static int add_table_name(char **p4tcpath, struct nlmsghdr *n)
{
	char full_tblname[P4TC_TABLE_NAMSIZ] = {0};
	char *cbname, *tblname;
	int ret;

	cbname = p4tcpath[PATH_CBNAME_IDX];
	tblname = p4tcpath[PATH_TBLNAME_IDX];

	if (cbname && tblname) {
		ret = concat_cb_name(full_tblname, cbname, tblname,
				     P4TC_TABLE_NAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "table name too long\n");
			return -1;
		}
	}

	if (!STR_IS_EMPTY(full_tblname))
		addattrstrz(n, MAX_MSG, P4TC_ENTRY_TBLNAME, full_tblname);

	return 0;
}

static int parse_table_entry_data(int cmd, int *argc_p, char ***argv_p,
				  char *p4tcpath[], struct nlmsghdr *n,
				  __u32 tbl_id)
{
	__u32 pipeid = 0;
	struct parse_state state = {0};
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 offset = 0;
	__u32 ids[2];
	int ret = 0;
	char *pname;

	pname = p4tcpath[PATH_TABLE_PNAME_IDX];

	while (argc > 0) {
		if (cmd == RTM_P4TC_CREATE ||
		    cmd == RTM_P4TC_UPDATE) {
			ret = parse_new_table_entry(&argc, &argv, n, &state,
						    p4tcpath, pname, ids,
						    &offset);
			if (ret < 0)
				return ret;

			ret = pipeid;
			goto add_attrs;

		} else {
			if (strcmp(*argv, "prio") == 0) {
				__u32 prio;

				NEXT_ARG();
				if (get_u32(&prio, *argv, 10)) {
					fprintf(stderr, "Invalid prio\n");
					ret = -1;
					goto out;
				}

				addattr32(n, MAX_MSG, P4TC_ENTRY_PRIO, prio);
			} else if (strcmp(*argv, "entry") == 0) {
				goto add_attrs;
			} else {
				ret = parse_table_keys(&argc, &argv, &state,
						       &offset, p4tcpath, pname,
						       tbl_id);
				if (ret < 0)
					goto out;
			}
		}
		argv++;
		argc--;
	}

	if (cmd == RTM_P4TC_DEL)
		addattr8(n, MAX_MSG, P4TC_ENTRY_WHODUNNIT, P4TC_ENTITY_TC);

add_attrs:
	ret = 0;
	if (add_table_name(p4tcpath, n) < 0)
		return -1;

	if (state.has_parsed_keys) {
		addattr_l(n, MAX_MSG, P4TC_ENTRY_KEY_BLOB, state.keyblob,
			  offset);
		addattr_l(n, MAX_MSG, P4TC_ENTRY_MASK_BLOB, state.maskblob,
			  offset);
	}

out:
	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

static int build_table_entry_root(int cmd, char **p4tcpath, struct nlmsghdr *n,
				  __u32 tbl_id)
{
	bool is_flush = cmd == RTM_P4TC_DEL;
	struct rtattr *count;
	struct rtattr *parm;

	if (is_flush)
		count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);

	parm = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);


	addattr8(n, MAX_MSG, P4TC_ENTRY_WHODUNNIT, P4TC_ENTITY_TC);

	if (add_table_name(p4tcpath, n))
		return -1;

	addattr_nest_end(n, parm);

	addattr32(n, MAX_MSG, P4TC_PATH, tbl_id);

	if (is_flush)
		addattr_nest_end(n, count);

	return 0;
}

static int parse_table_entry_filter(int *argc_p, char ***argv_p,
				    char *p4tcpath[], struct nlmsghdr *n,
				    __u32 tbl_id)
{
	struct parsedexpr *parsed_expr;
	struct typedexpr *typed_expr;
	struct rtattr *tail, *tail2;
	char **argv = *argv_p;
	int argc = *argc_p;

	tail = addattr_nest(n, MAX_MSG, P4TC_ENTRY_FILTER | NLA_F_NESTED);

	tail2 = addattr_nest(n, MAX_MSG, P4TC_FILTER_OP | NLA_F_NESTED);
	parsed_expr = parse_expr_args(&argc, (const char * const **)&argv,
				      NULL);
	if (parsed_expr->t == ET_ERR) {
		fprintf(stderr, "Failed to parse expr: %s\n",
			parsed_expr->errmsg);
		return -1;
	}

	typed_expr = type_expr(parsed_expr);
	if (typed_expr->t == ET_ERR) {
		fprintf(stderr, "Failed to type expr: %s\n",
			typed_expr->errmsg);
		return -1;
	}
	add_typed_expr(n, typed_expr);
	free_typedexpr(typed_expr);
	free_parsedexpr(parsed_expr);

	addattr_nest_end(n, tail2);
	addattr_nest_end(n, tail);


	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int parse_table_entry_flush_filter(int cmd, int *argc_p, char ***argv_p,
					  char *p4tcpath[], struct nlmsghdr *n,
					  __u32 tbl_id)
{
	struct rtattr *count;
	struct rtattr *parm;

	count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
	parm = addattr_nest(n, MAX_MSG,
			    P4TC_PARAMS | NLA_F_NESTED);

	if (add_table_name(p4tcpath, n) < 0)
		return -1;

	if (parse_table_entry_filter(argc_p, argv_p, p4tcpath, n,
				     tbl_id) < 0)
		return -1;

	addattr_nest_end(n, parm);

	addattr32(n, MAX_MSG, P4TC_PATH, tbl_id);

	addattr_nest_end(n, count);

	return 0;
}

static int parse_table_entry_dump_filter(int cmd, int *argc_p, char ***argv_p,
					 char *p4tcpath[], struct nlmsghdr *n,
					 __u32 tbl_id)
{
	struct rtattr *parm;

	parm = addattr_nest(n, MAX_MSG,
			    P4TC_PARAMS | NLA_F_NESTED);

	if (add_table_name(p4tcpath, n) < 0)
		return -1;

	if (parse_table_entry_filter(argc_p, argv_p, p4tcpath, n,
				     tbl_id) < 0)
		return -1;

	addattr_nest_end(n, parm);

	return 0;
}

int parse_table_entry(int cmd, int *argc_p, char ***argv_p,
		      char *p4tcpath[], struct nlmsghdr *n,
		      unsigned int *flags)
{
	__u32 pipeid = 0, tbl_id = 0;
	bool has_filter = false;
	char **argv = *argv_p;
	__u16 entry_count = 0;
	int argc = *argc_p;
	int ret;

	while (argc > 0) {
		if (strcmp(*argv, "pipeid") == 0) {
			NEXT_ARG();
			if (get_u32(&pipeid, *argv, 0) < 0)
				return -1;
		} else if (strcmp(*argv, "tblid") == 0) {
			NEXT_ARG();
			if (get_u32(&tbl_id, *argv, 0) < 0)
				return -1;
		} else if (strcmp(*argv, "filter") == 0) {
			if (has_filter) {
				fprintf(stderr, "Unable to add two filters");
				return -1;
			}

			NEXT_ARG();
			if (cmd == RTM_P4TC_GET) {
				ret = parse_table_entry_dump_filter(cmd, &argc,
								    &argv, p4tcpath,
								    n, tbl_id);
				if (ret < 0)
					return ret;

				addattr32(n, MAX_MSG, P4TC_PATH, tbl_id);
				has_filter = true;
				break;
			} else if (cmd == RTM_P4TC_DEL) {
				ret = parse_table_entry_flush_filter(cmd, &argc,
								     &argv, p4tcpath,
								     n, tbl_id);
				if (ret < 0)
					return ret;

				has_filter = true;
				break;
			} else {
				fprintf(stderr,
					"Filter may only be specified for dump and flush");
				return -1;
			}
		} else {
			struct rtattr *count;
			struct rtattr *parm;

			if (strcmp(*argv, "entry") == 0)
				NEXT_ARG();

			count = addattr_nest(n, MAX_MSG,
					     (entry_count + 1) | NLA_F_NESTED);
			parm = addattr_nest(n, MAX_MSG,
					    P4TC_PARAMS | NLA_F_NESTED);
			if (parse_table_entry_data(cmd, &argc, &argv, p4tcpath,
						   n, tbl_id) < 0)
				return -1;

			addattr_nest_end(n, parm);

			addattr32(n, MAX_MSG, P4TC_PATH, tbl_id);

			addattr_nest_end(n, count);
			entry_count++;
			continue;
		}

		argv++;
		argc--;
	}

	if (!entry_count) {
		if (cmd == RTM_P4TC_CREATE || cmd == RTM_P4TC_UPDATE) {
			fprintf(stderr,
				"Must specify entry for create or update");
			return -1;
		}
		if (!has_filter)
			build_table_entry_root(cmd, p4tcpath, n, tbl_id);
		*flags |= NLM_F_ROOT;
	}

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}
