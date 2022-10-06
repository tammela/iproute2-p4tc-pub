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
#include "p4tc_introspection.h"
#include "p4_types.h"

struct parse_state {
	struct tkey keys[P4TC_MAXPARSE_KEYS];
	bool has_parsed_keys;
	int num_keys;
	__u8 keyblob[P4TC_MAX_KEYSZ];
	__u8 maskblob[P4TC_MAX_KEYSZ];
};

static void parse_common(__u8 *keyblob, __u8 *maskblob,
			 struct p4_type_value *val, __u32 *offset, size_t sz)
{
	memcpy((keyblob + *offset), val->value, sz);
	memcpy((maskblob + *offset), val->mask, sz);
	*offset += sz;
}

static int parse_ipv4(struct parse_state *state, __u32 *offset, const char *argv)
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

struct mask_ops masks_ops[P4T_MAX] = {
	[P4T_IPV4ADDR] =  {
		.parse = parse_ipv4,
	},
};

static void print_entry_tm(FILE *f, const struct p4tc_table_entry_tm *tm)
{
	int hz = get_user_hz();

	if (tm->created != 0)
		print_uint(PRINT_ANY, "created", " created %u sec",
			   tm->created / hz);

	if (tm->lastused != 0)
		print_uint(PRINT_ANY, "last_used", " used %u sec",
			   tm->lastused / hz);

	if (tm->firstused != 0)
		print_uint(PRINT_ANY, "first_used", " firstused %u sec",
			   tm->firstused / hz);
	print_nl();
}

static int print_table_entry(struct nlmsghdr *n, struct rtattr *arg, FILE *f,
			     __u32 tbc_id, __u32 ti_id)
{
	struct rtattr *tb[P4TC_ENTRY_MAX + 1];
	unsigned int len;

	parse_rtattr_nested(tb, P4TC_ENTRY_MAX, arg);

	print_uint(PRINT_ANY, "tbcid", "table class id %u\n", tbc_id);
	print_nl();

	print_uint(PRINT_ANY, "tiid", "table instance id %u\n", ti_id);
	print_nl();

	if (tb[P4TC_ENTRY_TINAME])
		print_string(PRINT_ANY, "tiname", "table instance name %s\n",
			     RTA_DATA(tb[P4TC_ENTRY_TINAME]));

	if (tb[P4TC_ENTRY_PRIO]) {
		__u32 *prio = RTA_DATA(tb[P4TC_ENTRY_PRIO]);

		print_uint(PRINT_ANY, "prio", "entry priority %u\n", *prio);
	}

	if (!tb[P4TC_ENTRY_KEY_BLOB] || !tb[P4TC_ENTRY_MASK_BLOB]) {
		fprintf(stderr, "Must specify key and mask blobs");
		return -1;
	}

	len = RTA_PAYLOAD(tb[P4TC_ENTRY_KEY_BLOB]);
	if (len != RTA_PAYLOAD(tb[P4TC_ENTRY_MASK_BLOB])) {
		fprintf(stderr, "Key and mask blob's sizes must match");
		return -1;
	}

	switch (len << 3) {
	case 8: {
		const __u8 *keyblob = RTA_DATA(tb[P4TC_ENTRY_KEY_BLOB]);
		const __u8 *maskblob = RTA_DATA(tb[P4TC_ENTRY_MASK_BLOB]);

		print_0xhex(PRINT_ANY, "key", "key blob %02x\n", *keyblob);
		print_0xhex(PRINT_ANY, "mask", "mask blob %02x\n", *maskblob);
		break;
	}
	case 16: {
		const __u16 *keyblob = RTA_DATA(tb[P4TC_ENTRY_KEY_BLOB]);
		const __u16 *maskblob = RTA_DATA(tb[P4TC_ENTRY_MASK_BLOB]);

		print_0xhex(PRINT_ANY, "key", "key blob %04x\n", *keyblob);
		print_0xhex(PRINT_ANY, "mask", "mask blob %04x\n", *maskblob);
		break;
	}
	case 32: {
		const __u32 *keyblob = RTA_DATA(tb[P4TC_ENTRY_KEY_BLOB]);
		const __u32 *maskblob = RTA_DATA(tb[P4TC_ENTRY_MASK_BLOB]);

		print_0xhex(PRINT_ANY, "key", "key blob %08x\n", *keyblob);
		print_0xhex(PRINT_ANY, "mask", "mask blob %08x\n", *maskblob);
		break;
	}
	case 64: {
		const __u64 *keyblob = RTA_DATA(tb[P4TC_ENTRY_KEY_BLOB]);
		const __u64 *maskblob = RTA_DATA(tb[P4TC_ENTRY_MASK_BLOB]);

		print_0xhex(PRINT_ANY, "key", "key blob %16llx\n", *keyblob);
		print_0xhex(PRINT_ANY, "mask", "mask blob %16llx\n", *maskblob);
		break;
	}
	}

	if ((len << 3) > 64) {
		const __u8 *keyblob = RTA_DATA(tb[P4TC_ENTRY_KEY_BLOB]);
		const __u64 *keyblob1 = ((__u64 *)keyblob);
		const __u64 *keyblob2 = ((__u64 *)&keyblob[8]);
		const __u8 *maskblob = RTA_DATA(tb[P4TC_ENTRY_MASK_BLOB]);
		const __u64 *maskblob1 = ((__u64 *)maskblob);
		const __u64 *maskblob2 = ((__u64 *)&maskblob[8]);

		print_0xhex(PRINT_ANY, "key1", "key blob1 %16x\n", *keyblob1);
		print_0xhex(PRINT_ANY, "key2", "key blob2 %16x\n", *keyblob2);
		print_0xhex(PRINT_ANY, "mask1", "mask blob1 %16x\n", *maskblob1);
		print_0xhex(PRINT_ANY, "mask2", "mask blob2 %16x\n", *maskblob2);
	}

	if (tb[P4TC_ENTRY_ACT]) {
		print_string(PRINT_FP, NULL,
			     "    entry actions:", NULL);
		open_json_object("actions");
		print_nl();
		tc_print_action(f, tb[P4TC_ENTRY_ACT], 0);
		print_nl();
		close_json_object();
	}

	if (tb[P4TC_ENTRY_CREATE_WHODUNNIT]) {
		__u8 *whodunnit = RTA_DATA(tb[P4TC_ENTRY_CREATE_WHODUNNIT]);
		char name[NAME_MAX_LEN];

		if (p4tc_ctrltable_getbyid(*whodunnit, name) < 0)
			return -1;

		print_string(PRINT_ANY, "create_whodunnit", "create whodunnit %s\n", name);
	}

	if (tb[P4TC_ENTRY_UPDATE_WHODUNNIT]) {
		__u8 *whodunnit = RTA_DATA(tb[P4TC_ENTRY_UPDATE_WHODUNNIT]);
		char name[NAME_MAX_LEN];

		if (p4tc_ctrltable_getbyid(*whodunnit, name) < 0)
			return -1;

		print_string(PRINT_ANY, "update_whodunnit", "update whodunnit %s\n", name);
	}

	if (tb[P4TC_ENTRY_TM]) {
		struct p4tc_table_entry_tm *tm;

		tm = RTA_DATA(tb[P4TC_ENTRY_TM]);
		print_entry_tm(f, tm);
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

static int print_table_1(struct nlmsghdr *n, struct rtattr *arg,
			  FILE *f)
{
	__u32 *ids, tbc_id = 0, ti_id = 0;
	int cmd = n->nlmsg_type;
	struct rtattr *tb[P4TC_MAX + 1];

	parse_rtattr_nested(tb, P4TC_MAX, arg);

	if (tb[P4TC_PATH]) {
		ids = RTA_DATA(tb[P4TC_PATH]);
		tbc_id = ids[0];
		ti_id = ids[1];
	}

	if (cmd == RTM_DELP4TBENT && (n->nlmsg_flags & NLM_F_ROOT))
		print_table_entry_flush(n, tb[P4TC_COUNT], f);
	else
		print_table_entry(n, tb[P4TC_PARAMS], f, tbc_id, ti_id);

	return 0;
}

static int print_table_root(struct nlmsghdr *n, struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, arg);

	open_json_array(PRINT_JSON, "entries");
	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		open_json_object(NULL);
		print_table_1(n, tb[i], f);
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);

	return 0;
}

int print_table(struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1] = {};
	struct p4tcmsg *t = NLMSG_DATA(n);
	__u32 flags = n->nlmsg_flags;
	int len;

	open_json_object(NULL);
	switch (n->nlmsg_type) {
	case RTM_CREATEP4TBENT:
		if (flags & NLM_F_REPLACE)
			print_bool(PRINT_ANY, "updated", "updated ",
				   true);
		else
			print_bool(PRINT_ANY, "created", "created ",
				   true);
		break;
	case RTM_DELP4TBENT:
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
		print_string(PRINT_ANY, "pname", "pipeline name %s",
			     RTA_DATA(tb[P4TC_ROOT_PNAME]));
		print_nl();
	}
	if (t->pipeid) {
		print_uint(PRINT_ANY, "pipeid", "pipeline id %u", t->pipeid);
		print_nl();
	}
	close_json_object();

	if (tb[P4TC_ROOT]) {
		open_json_object(NULL);
		print_table_root(n, tb[P4TC_ROOT], (FILE *)arg);
		close_json_object();
	}

	return 0;
}

#define P4TC_FLAGS_TNAME      0x1
#define P4TC_FLAGS_TTYPE_NAME 0x2
#define P4TC_FLAGS_PNAME      0x4
#define P4TC_FLAGS_TTYPE_ID   0x8
#define P4TC_FLAGS_TINST_ID   0x10

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

#define PATH_TABLE_OBJ_IDX 1
#define PATH_TABLE_PNAME_IDX 0

#define MAX_PATH_COMPONENTS 5

#define do_ipv4_mask(addr, sz) (htonl(~0u << ((sz) - addr.bitlen)))

static int __parse_table_keys(struct parse_state *state, __u32 *offset,
			      const char *argv,
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
		if (type->parse_p4t(&val, argv, 10) < 0) {
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

static int parse_table_field(int *argc_p, char ***argv_p,
			     struct parse_state *state, __u32 *offset)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	struct p4_type_s *type;
	__u32 bitsz;

	NEXT_ARG();

	type = get_p4type_byarg(*argv, &bitsz);
	if (!type)
		return -1;

	NEXT_ARG();

	/* XXX: Lets see if we keep this in the long run.
	 * something like this when no introspection (processed after
	 * you hit enter):
	 * tc p4 create ptables/table/mysrc ip/dstAddr ipv4 192.168.0.0/16
	 */
	if (__parse_table_keys(state, offset, *argv, type) < 0)
		return -1;

	*argv_p = argv;
	*argc_p = argc;

	return 0;
}

static int parse_table_keys(int *argc_p, char ***argv_p,
			    struct parse_state *state,
			    __u32 *offset, char **p4tcpath,
			    __u32 tbc_id)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret = 0;

	if (!state->has_parsed_keys) {
		state->num_keys = p4tc_get_table_keys(state->keys,
						      p4tcpath[PATH_TABLE_PNAME_IDX],
						      p4tcpath[PATH_TBCNAME_IDX],
						      tbc_id);
	}

	if (state->num_keys > 0) {
		struct tkey *key;

		state->has_parsed_keys = true;
		key = p4tc_find_table_key(state->keys, *argv, state->num_keys);
		if (key) {
			NEXT_ARG();
			if (__parse_table_keys(state, offset, *argv,
					       key->type) < 0) {
				ret = -1;
				goto out;
			}
		} else {
			fprintf(stderr, "Unknown arg %s\n", *argv);
			ret = -1;
			goto out;
		}
	} else { /* No introspection */
		if (parse_table_field(&argc, &argv, state, offset) < 0) {
			ret = -1;
			goto out;
		}
	}

out:
	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

static int parse_table_data(int cmd, int *argc_p, char ***argv_p,
			    char *p4tcpath[], struct nlmsghdr *n,
			    unsigned int *flags)
{
	__u32 pipeid = 0, prio = 0, tbc_id = 0, ti_id = 0;
	char full_tbcname[TCLASSNAMSIZ] = {0};
	struct parse_state state = {0};
	struct rtattr *count = NULL;
	struct rtattr *parm = NULL;
	char **argv = *argv_p;
	int argc = *argc_p;
	int parsed_keys = 0;
	__u32 offset = 0;
	int ret = 0;
	char *cbname, *tbcname;
	/* Holds two ids: tbcid and tinstid */
	__u32 ids[2];

	cbname = p4tcpath[PATH_CBNAME_IDX];
	tbcname = p4tcpath[PATH_TBCNAME_IDX];

	while (argc > 0) {
		if (cmd == RTM_CREATEP4TBENT) {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "tinstid") == 0) {
				NEXT_ARG();
				if (get_u32(&ti_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "tbcid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbc_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "prio") == 0) {
				NEXT_ARG();
				if (get_u32(&prio, *argv, 10)) {
					fprintf(stderr, "Invalid prio\n");
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "action") == 0) {
				if (!count)
					count = addattr_nest(n, MAX_MSG, 1);
				if (!parm)
					parm = addattr_nest(n, MAX_MSG, P4TC_PARAMS);

				if (parse_action(&argc, &argv, P4TC_ENTRY_ACT, n)) {
					fprintf(stderr, "Illegal action\"\n");
					ret = -1;
					goto out;
				}
			} else {
				ret = parse_table_keys(&argc, &argv, &state,
						       &offset, p4tcpath, tbc_id);
				if (ret < 0)
					goto out;
				parsed_keys++;
			}
		} else {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "tinstid") == 0) {
				NEXT_ARG();
				if (get_u32(&ti_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "tbcid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbc_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "prio") == 0) {
				NEXT_ARG();
				if (get_u32(&prio, *argv, 10)) {
					fprintf(stderr, "Invalid prio\n");
					ret = -1;
					goto out;
				}
			} else {
				ret = parse_table_keys(&argc, &argv, &state,
						       &offset, p4tcpath, tbc_id);
				if (ret < 0)
					goto out;
				parsed_keys++;
			}
		}
		argv++;
		argc--;
	}

	if (!prio && !parsed_keys)
		*flags = NLM_F_ROOT;
	if (!((*flags & NLM_F_ROOT) && cmd == RTM_GETP4TBENT) && !count)
		count = addattr_nest(n, MAX_MSG, 1);

	if (!parm)
		parm = addattr_nest(n, MAX_MSG, P4TC_PARAMS);

	ret = 0;
	if (cbname && tbcname) {
		ret = concat_cb_name(full_tbcname, cbname, tbcname,
				     TCLASSNAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "table class name too long\n");
			return -1;
		}
	}

	if (!STR_IS_EMPTY(full_tbcname))
		addattrstrz(n, MAX_MSG, P4TC_ENTRY_TBCNAME, full_tbcname);
	if (p4tcpath[PATH_TINAME_IDX])
		addattrstrz(n, MAX_MSG, P4TC_ENTRY_TINAME,
			    p4tcpath[PATH_TINAME_IDX]);

	if (parsed_keys) {
		addattr_l(n, MAX_MSG, P4TC_ENTRY_KEY_BLOB, state.keyblob, offset);
		addattr_l(n, MAX_MSG, P4TC_ENTRY_MASK_BLOB, state.maskblob, offset);
	}

	addattr8(n, MAX_MSG, P4TC_ENTRY_WHODUNNIT, P4TC_ENTITY_TC);

	if (prio)
		addattr32(n, MAX_MSG, P4TC_ENTRY_PRIO, prio);

	if (parm)
		addattr_nest_end(n, parm);

	ids[0] = tbc_id;
	ids[1] = ti_id;
	addattr_l(n, MAX_MSG, P4TC_PATH, ids, 2 * sizeof(__u32));

	if (count)
		addattr_nest_end(n, count);

	ret = pipeid;

out:
	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

static int tc_table_cmd(int cmd, unsigned int flags, int *argc_p,
			char ***argv_p)
{
	char *p4tcpath[MAX_PATH_COMPONENTS] = {NULL};
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *root;
	int obj_type;
	int ret;

	struct {
		struct nlmsghdr n;
		struct p4tcmsg t;
		char buf[MAX_MSG];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct p4tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | flags,
		.n.nlmsg_type = cmd,
	};
	argc -= 1;
	argv += 1;

	if (!argc)
		return -1;

	parse_path(*argv, p4tcpath);
	if (!p4tcpath[PATH_TABLE_OBJ_IDX])
		return -1;

	obj_type = get_obj_type(p4tcpath[PATH_TABLE_OBJ_IDX]);
	if (obj_type <= 0 || obj_type != P4TC_OBJ_TABLE_ENTRY)
		return -1;
	req.t.obj = P4TC_OBJ_TABLE_ENTRY;
	argc -= 1;
	argv += 1;

	if (p4tcpath[PATH_TABLE_PNAME_IDX])
		addattrstrz(&req.n, MAX_MSG, P4TC_ROOT_PNAME,
			p4tcpath[PATH_TABLE_PNAME_IDX]);

	root = addattr_nest(&req.n, MAX_MSG, P4TC_ROOT);

	ret = parse_table_data(cmd, &argc, &argv, p4tcpath, &req.n, &flags);
	if (ret < 0)
		return ret;
	req.t.pipeid = ret;

	req.n.nlmsg_flags = NLM_F_REQUEST | flags,
	addattr_nest_end(&req.n, root);

	if (cmd == RTM_GETP4TBENT) {
		if (flags & NLM_F_ROOT) {
			int msg_size;

			msg_size = NLMSG_ALIGN(req.n.nlmsg_len) -
				NLMSG_ALIGN(sizeof(struct nlmsghdr));
			if (rtnl_dump_request(&rth, RTM_GETP4TBENT,
					      (void *)&req.t, msg_size) < 0) {
				perror("Cannot send dump request");
				return -1;
			}

			new_json_obj(json);
			if (rtnl_dump_filter(&rth, print_table, stdout) < 0) {
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
			print_table(ans, stdout);
			delete_json_obj();
		}
	} else {
		if (rtnl_talk(&rth, &req.n, NULL) < 0) {
			fprintf(stderr, "We have an error talking to the kernel\n");
			return -1;
		}
	}

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

int do_p4_table(int argc, char **argv)
{
	int ret = 0;

	while (argc > 0) {
		if (matches(*argv, "create") == 0) {
			ret = tc_table_cmd(RTM_CREATEP4TBENT,
					   NLM_F_EXCL | NLM_F_CREATE, &argc,
					   &argv);
		} else if (matches(*argv, "update") == 0) {
			ret = tc_table_cmd(RTM_CREATEP4TBENT, NLM_F_REPLACE,
					   &argc, &argv);
		} else if (matches(*argv, "get") == 0) {
			ret = tc_table_cmd(RTM_GETP4TBENT, 0, &argc, &argv);
		} else if (matches(*argv, "delete") == 0) {
			ret = tc_table_cmd(RTM_DELP4TBENT, 0, &argc, &argv);
		} else {
			fprintf(stderr,
				"Command \"%s\" is unknown, try \"tc table help\".\n",
				*argv);
			return -1;
		}

		if (ret < 0)
			return -1;
	}

	return 0;
}
