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
#include "names.h"
#include "tc_common.h"
#include "tc_util.h"
#include "p4tc_names.h"
#include "p4tc_common.h"
#include "p4_types.h"
#include "p4_tc_json.h"

static void parse_common(__u8 *keyblob, __u8 *maskblob,
			 struct p4_type_value *val, __u32 *offset, size_t sz)
{
	memcpy((keyblob + *offset), val->value, sz);
	memcpy((maskblob + *offset), val->mask, sz);
	*offset += sz;
}

static int parse_ipv4(struct parse_state *state, __u32 *offset,
		      const char *argv)
{
	struct p4_type_value val;
	struct p4_type_s *type = get_p4type_byid(P4T_IPV4ADDR);
	__u32 sz = type->bitsz >> 3;
	__u32 addr;
	__u32 mask;

	val.value = &addr;
	val.mask = &mask;

	if (type->parse_p4t(&val, argv, 0) < 0) {
		fprintf(stderr, "Invalid ipv4 address %s\n", argv);
		return -1;
	}
	parse_common(state->keyblob, state->maskblob, &val, offset, sz);

	return 0;
}

struct mask_ops {
	int (*parse)(struct parse_state *state, __u32 *offset,
		     const char *argv);
};

struct mask_ops masks_ops[P4T_MAX] = {
	[P4T_IPV4ADDR] =  {
		.parse = parse_ipv4,
	},
};

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
		      const char *prefix, struct table *table, __u32 tbl_id)
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
			print_uint(PRINT_ANY, "tblid", " table: \?\?\?(id %u)\n",
				   tbl_id);
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
			fprintf(stderr, "Size mismatch: table %db key %dB mask %ldB",
				table->ksize, len,
				RTA_PAYLOAD(tb[P4TC_ENTRY_MASK_BLOB]));
		else
			fprintf(stderr, "Size mismatch: key %dB mask %ldB", len,
				RTA_PAYLOAD(tb[P4TC_ENTRY_MASK_BLOB]));
		return -1;
	}

	if (table)
		p4_tc_print_key_data(table, RTA_DATA(tb[P4TC_ENTRY_KEY_BLOB]),
				     RTA_DATA(tb[P4TC_ENTRY_MASK_BLOB]), len, f,
				     prefix);

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

	if (tb[P4TC_ENTRY_STATIC])
		print_string(PRINT_ANY, "static", "    static %s\n",
			   "true");
	else
		print_string(PRINT_ANY, "static", "    static %s\n",
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

static int print_table_1(struct nlmsghdr *n, struct p4_tc_pipeline *pipe,
			 struct rtattr *arg, FILE *f)
{
	int cmd = n->nlmsg_type;
	__u32 *tbl_id = NULL;
	struct table *table = NULL;
	struct rtattr *tb[P4TC_MAX + 1];

	parse_rtattr_nested(tb, P4TC_MAX, arg);

	if (tb[P4TC_PATH])
		tbl_id = RTA_DATA(tb[P4TC_PATH]);

	if (tbl_id) {
		if (pipe) {
			table = p4tc_find_table_byid(pipe, *tbl_id);
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

static int print_table_root(struct nlmsghdr *n, struct p4_tc_pipeline *pipe,
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
	struct p4_tc_pipeline *pipe = NULL;
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
		pipe = p4_tc_import_json(pname);
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

	return 0;
}

#define P4TC_FLAGS_TNAME      0x1
#define P4TC_FLAGS_TTYPE_NAME 0x2
#define P4TC_FLAGS_PNAME      0x4
#define P4TC_FLAGS_TTYPE_ID   0x8

static inline int copy_to_key(__u8 *key, __u8 *mask, const __u8 *valkey,
			      const __u8 *valmask, __u16 *off, __u16 sz,
			      __u16 maxsz)
{
	if (!key || !mask) {
		fprintf(stderr,
			"Must specify key size before key attributes\n");
		return -1;
	}

	if (*off + sz > maxsz) {
		fprintf(stderr, "Exceeds maximum key size\n");
		return -1;
	}

	memcpy(key + *off, valkey, sz);
	memcpy(mask + *off, valmask, sz);
	*off += sz;

	return 0;
}

#define MAX_PATH_COMPONENTS 5

#define do_ipv4_mask(addr, sz) (htonl(~0u << ((sz) - addr.bitlen)))

static int __parse_table_keys(struct parse_state *state, __u32 *offset,
			      const char *argv, __u32 bitsz,
			      struct p4_type_s *type)
{
	struct mask_ops *mask_op = &masks_ops[type->containid];
	int ret;

	if (mask_op->parse) {
		ret = mask_op->parse(state, offset, argv);
		if (ret < 0)
			return ret;
	} else {
		int bytesz = type->bitsz >> 3;
		__u8 *mask = calloc(1, bytesz);
		__u8 *value = calloc(1, bytesz);
		struct p4_type_value val;
		int i;

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

		for (i = 0; i < bytesz; i++)
			mask[i] = 0xFF;

		parse_common(state->keyblob, state->maskblob, &val, offset,
			     bytesz);

		free(value);
		free(mask);
	}

	return 0;
}

static int parse_table_keys(int *argc_p, char ***argv_p,
			    struct parse_state *state, __u32 *offset,
			    char **p4tcpath, const char *pname, __u32 tbl_id)
{
	const char *cbname = p4tcpath[PATH_CBNAME_IDX];
	const char *tblname = p4tcpath[PATH_TBLNAME_IDX];
	char full_tblname[TABLENAMSIZ] = {0};
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret = 0;
	struct key_fields_list *key;
	struct p4_tc_pipeline *p;
	struct p4_type_s *typ;
	struct table *t;

	p = p4_tc_import_json(pname);
	if (!p) {
		fprintf(stderr, "parse keys - Unable to find pipeline %s\n",
			p4tcpath[PATH_TABLE_PNAME_IDX]);
		return -1;
	}

	if (concat_cb_name(full_tblname, cbname, tblname, TABLENAMSIZ) < 0) {
		fprintf(stderr, "Table name to long %s/%s\n", cbname, tblname);
		return -1;
	}

	t = p4tc_find_table(p, full_tblname);
	if (!t) {
		fprintf(stderr, "Unable to find table %s\n", tblname);
		return -1;
	}

	state->has_parsed_keys = true;
	key = p4tc_find_table_keyfield(t, 1, *argv);
	if (!key) {
		fprintf(stderr, "Unable to find key field %s in introspection file\n",
			*argv);
		return -1;
	}
	typ = get_p4type_byname(key->type);
	if (!typ) {
		fprintf(stderr, "Unable to find type %s\n", key->type);
		return -1;
	}
	if (key) {
		NEXT_ARG();
		if (__parse_table_keys(state, offset, *argv,
				       0, typ) < 0) {
			ret = -1;
			goto out;
		}
	} else {
		fprintf(stderr, "Unknown arg %s\n", *argv);
		ret = -1;
		goto out;
	}

out:
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

/* This function allows for the binding of many actions to a table entry.
 * We are aware P4 doesn't allow for this, but we are making an exception since
 * something of this sort is perfectly legal and reasonable for TC.
 */
static int parse_table_action(int *argc_p, char ***argv_p, char **p4tcpath,
			      struct nlmsghdr *n)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int prio = 0;
	int ret = 0;
	int eap = 0;
	struct rtattr *tail, *tail2, *tail3;
	char *pname, *cbname;

	pname = p4tcpath[PATH_TABLE_PNAME_IDX];
	cbname = p4tcpath[PATH_CBNAME_IDX];

	tail2 = addattr_nest(n, MAX_MSG, P4TC_ENTRY_ACT | NLA_F_NESTED);

	while (argc > 0) {
		if (strcmp(*argv, "action") == 0) {
			argc--;
			argv++;
			eap = 1;
		} else {
			bool introspect_global = false;
			char *actname = *argv;
			__u32 flag = 0;

			eap = 0;

			tail = addattr_nest(n, MAX_MSG, ++prio);
			if (is_relative_path(actname)) {
				char full_actname[ACTNAMSIZ];

				snprintf(full_actname, ACTNAMSIZ, "%s/%s/%s",
					 pname, cbname, actname);
				actname = full_actname;
				introspect_global = true;
			}

			NEXT_ARG_FWD();
			tail3 = addattr_nest(n, MAX_MSG,
					     TCA_ACT_OPTIONS | NLA_F_NESTED);
			ret = parse_dyna_tbl_act(&argc, &argv, &actname,
						 introspect_global, n);
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
				struct nla_bitfield32 flags =
				{ flag, flag };

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
	fprintf(stderr, "parse_table_action: bad value (%d:%s)!\n", argc,
		*argv);
	return -1;
}

static int parse_table_attrs(int *argc_p, char ***argv_p, struct nlmsghdr *n)
{
	char **argv = *argv_p;
	struct rtattr *parm;
	int argc = *argc_p;

	parm = addattr_nest(n, MAX_MSG, P4TC_ENTRY_TBL_ATTRS | NLA_F_NESTED);

	while (argc > 0) {
		if (strcmp(*argv, "default_hit_action") == 0) {
			NEXT_ARG();
			if (parse_table_default_action(&argc, &argv, n,
						       P4TC_ENTRY_TBL_ATTRS_DEFAULT_HIT))
				return -1;
		} else if (strcmp(*argv, "default_miss_action") == 0) {
			NEXT_ARG();
			if (parse_table_default_action(&argc, &argv, n,
						       P4TC_ENTRY_TBL_ATTRS_DEFAULT_MISS))
				return -1;
		} else if (strcmp(*argv, "tbl_permissions") == 0) {
			__u16 permissions;

			NEXT_ARG();
			if (get_u16(&permissions, *argv, 16) < 0)
				return -1;

			addattr16(n, MAX_MSG, P4TC_ENTRY_TBL_ATTRS_PERMISSIONS,
				  permissions);
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
	struct p4_tc_arch_json *arch_info = NULL;
	__u32 pipeid = 0, tbl_id = 0, prio = 0;
	int ret, parsed_keys = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 permissions;

	while (argc > 0) {
		if (strcmp(*argv, "pipeid") == 0) {
			NEXT_ARG();
			if (get_u32(&pipeid, *argv, 10) < 0) {
				pipeid = -1;
				goto out;
			}
		} else if (strcmp(*argv, "tblid") == 0) {
			NEXT_ARG();
			if (get_u32(&tbl_id, *argv, 10) < 0) {
				pipeid = -1;
				goto out;
			}
		} else if (strcmp(*argv, "prio") == 0) {
			__u32 prio;

			NEXT_ARG();
			if (get_u32(&prio, *argv, 10)) {
				fprintf(stderr, "Invalid prio\n");
				pipeid = -1;
				goto out;
			}
			addattr32(n, MAX_MSG, P4TC_ENTRY_PRIO, prio);
		} else if (strcmp(*argv, "action") == 0) {
			if (parse_table_action(&argc, &argv, p4tcpath, n)) {
				fprintf(stderr, "Illegal action\n");
				pipeid = -1;
				goto out;
			}
			continue;
		} else if (strcmp(*argv, "permissions") == 0) {
			NEXT_ARG();
			if (get_u16((__u16*)&permissions, *argv, 16) < 0) {
				pipeid = -1;
				goto out;
			}

			addattr16(n, MAX_MSG, P4TC_ENTRY_PERMISSIONS,
				  (__u16)permissions);
		} else if (strcmp(*argv, "tbl_attrs") == 0) {
			NEXT_ARG();
			if (parse_table_attrs(&argc, &argv, n))
				return -1;
		} else if (strcmp(*argv, "static") == 0) {
			__u8 is_static = 1;

			addattr8(n, MAX_MSG, P4TC_ENTRY_STATIC, is_static);
		} else if (strcmp(*argv, "aging") == 0) {
			struct profile *profile;
			__u64 aging;

			NEXT_ARG();
			if (get_u64(&aging, *argv, 0) < 0)
				return -1;
			if (arch_info) {
				profile = p4tc_find_profile_by_aging(arch_info,
								     aging);
				if (!profile) {
					fprintf(stderr,
						"Unable to find profile\n");
					return -1;
				}
			}
			addattr64(n, MAX_MSG, P4TC_ENTRY_AGING, aging);
		} else if (strcmp(*argv, "arch_file") == 0) {
			NEXT_ARG();
			arch_info = p4_tc_import_arch_json(*argv);
			if (!arch_info)
				return -1;
		} else {
			ret = parse_table_keys(&argc, &argv, state,
					       offset, p4tcpath, pname, tbl_id);
			if (ret < 0) {
				pipeid = ret;
				goto out;
			}
			parsed_keys++;
		}

		argv++;
		argc--;
	}

	addattr8(n, MAX_MSG, P4TC_ENTRY_WHODUNNIT, P4TC_ENTITY_TC);
out:
	ids[0] = tbl_id;
	ids[1] = prio;
	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

int parse_table_entry_data(int cmd, int *argc_p, char ***argv_p,
			   char *p4tcpath[], struct nlmsghdr *n,
			   unsigned int *flags)
{
	__u32 pipeid = 0, prio = 0, tbl_id = 0;
	char full_tblname[TABLENAMSIZ] = {0};
	struct parse_state state = {0};
	struct rtattr *count = NULL;
	struct rtattr *parm = NULL;
	char **argv = *argv_p;
	int argc = *argc_p;
	int parsed_keys = 0;
	__u32 offset = 0;
	int ret = 0;
	char *pname, *cbname, *tblname;
	__u32 ids[2];

	pname = p4tcpath[PATH_TABLE_PNAME_IDX];
	cbname = p4tcpath[PATH_CBNAME_IDX];
	tblname = p4tcpath[PATH_TBLNAME_IDX];

	if (cmd == RTM_P4TC_CREATE ||
	    cmd == RTM_P4TC_UPDATE) {
		count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
		parm = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);
	}

	while (argc > 0) {
		if (cmd == RTM_P4TC_CREATE ||
		    cmd == RTM_P4TC_UPDATE) {
			ret = parse_new_table_entry(&argc, &argv, n, &state,
						       p4tcpath, pname, ids,
						       &offset);
			if (ret < 0)
				return ret;

			ret = pipeid;

			tbl_id = ids[0];
			prio = ids[1];
		} else {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "tblid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbl_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "prio") == 0) {
				__u32 prio;

				if (!count)
					count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
				if (!parm)
					parm = addattr_nest(n, MAX_MSG,
							    P4TC_PARAMS | NLA_F_NESTED);

				NEXT_ARG();
				if (get_u32(&prio, *argv, 10)) {
					fprintf(stderr, "Invalid prio\n");
					ret = -1;
					goto out;
				}

				addattr32(n, MAX_MSG, P4TC_ENTRY_PRIO, prio);
			} else {
				ret = parse_table_keys(&argc, &argv, &state,
						       &offset, p4tcpath, pname,
						       tbl_id);
				if (ret < 0)
					goto out;
				parsed_keys++;
			}
		}
		argv++;
		argc--;
	}

	if (!prio && !(state.has_parsed_keys))
		*flags = NLM_F_ROOT;
	if (!((*flags & NLM_F_ROOT) && cmd == RTM_P4TC_GET) && !count)
		count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);

	if (!parm)
		parm = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

	if (cmd == RTM_P4TC_DEL)
		addattr8(n, MAX_MSG, P4TC_ENTRY_WHODUNNIT, P4TC_ENTITY_TC);

	ret = 0;
	if (cbname && tblname) {
		ret = concat_cb_name(full_tblname, cbname, tblname,
				     TABLENAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "table name too long\n");
			return -1;
		}
	}

	if (!STR_IS_EMPTY(full_tblname))
		addattrstrz(n, MAX_MSG, P4TC_ENTRY_TBLNAME, full_tblname);

	if (state.has_parsed_keys) {
		addattr_l(n, MAX_MSG, P4TC_ENTRY_KEY_BLOB, state.keyblob,
			  offset);
		addattr_l(n, MAX_MSG, P4TC_ENTRY_MASK_BLOB, state.maskblob,
			  offset);
	}

	if (parm)
		addattr_nest_end(n, parm);

	addattr32(n, MAX_MSG, P4TC_PATH, tbl_id);

	if (count)
		addattr_nest_end(n, count);

	ret = pipeid;

out:
	*argc_p = argc;
	*argv_p = argv;

	return ret;
}