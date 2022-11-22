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
#include <linux/p4tc.h>

#include "utils.h"
#include "tc_common.h"
#include "tc_util.h"
#include "p4tc_common.h"
#include "p4_types.h"
#include "p4tc_cmds.h"

static struct hlist_head kernel_metadata_list = {};

static struct p4_metat_s pktlen_meta = {
	.id = P4TC_KERNEL_META_PKTLEN,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "pktlen",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s datalen_meta = {
	.id = P4TC_KERNEL_META_DATALEN,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "datalen",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbmark_meta = {
	.id = P4TC_KERNEL_META_SKBMARK,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "skbmark",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s tcindex_meta = {
	.id = P4TC_KERNEL_META_TCINDEX,
	.containid = P4T_U16,
	.startbit = 0,
	.endbit = 15,
	.name = "tcindex",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbhash_meta = {
	.id = P4TC_KERNEL_META_SKBHASH,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "skbhash",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbprio_meta = {
	.id = P4TC_KERNEL_META_SKBPRIO,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "skbprio",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s ifindex_meta = {
	.id = P4TC_KERNEL_META_IFINDEX,
	.containid = P4T_S32,
	.startbit = 0,
	.endbit = 31,
	.name = "ifindex",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s iif_meta = {
	.id = P4TC_KERNEL_META_SKBIIF,
	.containid = P4T_DEV,
	.startbit = 0,
	.endbit = 31,
	.name = "iif",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s protocol_meta = {
	.id = P4TC_KERNEL_META_PROTOCOL,
	.containid = P4T_BE16,
	.startbit = 0,
	.endbit = 15,
	.name = "skbproto",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbptype_meta = {
	.id = P4TC_KERNEL_META_PKTYPE,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 2,
	.name = "skbptype",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbidf_meta = {
	.id = P4TC_KERNEL_META_IDF,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 0,
	.name = "skbidf",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbipsum_meta = {
	.id = P4TC_KERNEL_META_IPSUM,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 1,
	.name = "skbipsum",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbfclon_meta = {
	.id = P4TC_KERNEL_META_FCLONE,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 1,
	.name = "skbfclon",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbpeek_meta = {
	.id = P4TC_KERNEL_META_PEEKED,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 0,
	.name = "skbpeek",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skboook_meta = {
	.id = P4TC_KERNEL_META_OOOK,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 0,
	.name = "skboook",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbqmap_meta = {
	.id = P4TC_KERNEL_META_QMAP,
	.containid = P4T_U16,
	.startbit = 0,
	.endbit = 15,
	.name = "skbqmap",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s ptypeoff_meta = {
	.id = P4TC_KERNEL_META_PTYPEOFF,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 7,
	.name = "ptypeoff",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s cloneoff_meta = {
	.id = P4TC_KERNEL_META_CLONEOFF,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 7,
	.name = "cloneoff",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s direction_meta = {
	.id = P4TC_KERNEL_META_DIRECTION,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 0,
	.name = "direction",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s ptclnoff_meta = {
	.id = P4TC_KERNEL_META_PTCLNOFF,
	.containid = P4T_U16,
	.startbit = 0,
	.endbit = 15,
	.name = "ptclnoff",
	.pipeid = 0,
	.pname = "kernel",
};

struct p4_metat_s *get_meta_byname(const char *pname, const char *name)
{
	struct hlist_node *m, *tmp_child;

	hlist_for_each_safe(m, tmp_child, &kernel_metadata_list) {
		struct p4_metat_s *meta;

		meta = container_of(m, struct p4_metat_s, hlist);
		if (strcmp(meta->pname, pname) == 0 &&
		    strnlen(name, METANAMSIZ) == strnlen(meta->name, METANAMSIZ) &&
		    strncasecmp(meta->name, name, strlen(name)) == 0)
			return meta;
	}

	return NULL;
}

struct p4_metat_s *get_meta_byid(const __u32 pipeid, const __u32 id)
{
	struct hlist_node *m, *tmp_child;

	hlist_for_each_safe(m, tmp_child, &kernel_metadata_list) {
		struct p4_metat_s *meta;

		meta = container_of(m, struct p4_metat_s, hlist);
		if (pipeid == meta->pipeid &&
		    id == meta->id)
			return meta;
	}

	return NULL;
}

void register_new_metadata(struct p4_metat_s *meta)
{
	hlist_add_head(&meta->hlist, &kernel_metadata_list);
}

void register_kernel_metadata(void)
{
	register_new_metadata(&pktlen_meta);
	register_new_metadata(&datalen_meta);
	register_new_metadata(&skbmark_meta);
	register_new_metadata(&tcindex_meta);
	register_new_metadata(&skbhash_meta);
	register_new_metadata(&skbprio_meta);
	register_new_metadata(&ifindex_meta);
	register_new_metadata(&iif_meta);
	register_new_metadata(&skbidf_meta);
	register_new_metadata(&protocol_meta);
	register_new_metadata(&skbipsum_meta);
	register_new_metadata(&skbfclon_meta);
	register_new_metadata(&skbpeek_meta);
	register_new_metadata(&skboook_meta);
	register_new_metadata(&skbqmap_meta);
	register_new_metadata(&ptypeoff_meta);
	register_new_metadata(&skbptype_meta);
	register_new_metadata(&cloneoff_meta);
	register_new_metadata(&ptclnoff_meta);
	register_new_metadata(&direction_meta);
}

void unregister_kernel_metadata(void)
{
	struct hlist_node *n, *tmp_meta;

	hlist_for_each_safe(n, tmp_meta, &kernel_metadata_list) {
		struct p4_metat_s *meta;

		meta = container_of(n, struct p4_metat_s, hlist);
		hlist_del(&meta->hlist);
	}
}

#include "p4tc_common.h"

static void p4template_usage(void)
{
	fprintf(stderr,
		"usage: tc p4template create | update pipeline/pname [PIPEID] OPTS\n"
		"       tc p4tempalte del | get pipeline/[pname] [PIPEID]\n"
		"Where:  OPTS := NUMTABLES PREACTIONS POSTACTIONS STATE\n"
		"	PIPEID := pipeid <32 bit pipeline id>\n"
		"	NUMTABLES := numtables <16 bit numtables>\n"
		"	PREACTIONS := preactions <ACTISPEC>\n"
		"	POSTACTIONS := postactions <ACTISPEC>\n"
		"	ACTISPEC := <ACTNAMESPEC> <INDEXSPEC>\n"
		"	ACTNAMESPEC := action <ACTNAME>\n"
		"	INDEXSPEC := index <32 bit indexvalue>\n"
		"	Example ACTNAME is gact, mirred, csum, etc\n"
		"	STATE := state ready\n"
		"\n");

	exit(-1);
}

static int print_register_flush(struct nlmsghdr *n, struct rtattr *cnt_attr,
				FILE *f)
{
	const __u32 *cnt = RTA_DATA(cnt_attr);

	print_uint(PRINT_ANY, "count", "    register flush count %u", *cnt);
	print_nl();

	return 0;
}

static int print_register_template_value(struct rtattr *arg,
					 struct p4tc_u_register *parm,
					 struct p4_type_s *type,
					 char *name, FILE *f)
{
	if (arg && type) {
		size_t container_bytesz = type->bitsz >> 3;
		void *value = RTA_DATA(arg);
		__u32 len = 0, value_len;
		struct p4_type_value val;
		void *mask;
		int i = 0;

		mask = calloc(1, container_bytesz);
		if (!mask)
			return -1;

		value_len = RTA_PAYLOAD(arg);
		if (parm->flags & P4TC_REGISTER_FLAGS_INDEX) {
			SPRINT_BUF(prefix);

			val.value = value;
			val.mask = mask;

			snprintf(prefix, SPRINT_BSIZE, "%s[%d]", name,
				 parm->index);

			print_string(PRINT_FP, NULL, "        ", NULL);
			if (type->print_p4t)
				type->print_p4t(prefix, prefix, &val, f);
			print_nl();
		} else {
			open_json_array(PRINT_JSON, "values");
			while (len < value_len) {
				SPRINT_BUF(prefix);

				val.value = value;
				val.mask = mask;

				snprintf(prefix, SPRINT_BSIZE, "%s[%d]", name,
					 i);
				open_json_object(NULL);
				print_string(PRINT_FP, NULL, "        ", NULL);
				if (type->print_p4t)
					type->print_p4t(prefix, prefix, &val,
							f);
				print_nl();
				close_json_object();

				value += (container_bytesz);
				len += (container_bytesz);
				i++;
			}
			close_json_array(PRINT_JSON, NULL);
		}

		free(mask);
	}

	return 0;
}

static int print_register_template(struct nlmsghdr *n, struct rtattr *arg,
				   __u32 reg_id, FILE *f)
{
	struct rtattr *tb[P4TC_ACT_MAX + 1];
	struct p4tc_u_register *parm;
	char *name;

	parse_rtattr_nested(tb, P4TC_REGISTER_MAX, arg);

	if (tb[P4TC_REGISTER_NAME]) {
		name = RTA_DATA(tb[P4TC_REGISTER_NAME]);
		print_string(PRINT_ANY, "regname", "    register name %s\n", name);
	}
	if (reg_id)
		print_uint(PRINT_ANY, "regid", "    register id %u\n", reg_id);

	if (tb[P4TC_REGISTER_INFO]) {
		struct p4_type_s *type = NULL;

		parm = RTA_DATA(tb[P4TC_REGISTER_INFO]);

		if (parm->flags & P4TC_REGISTER_FLAGS_DATATYPE) {
			type = get_p4type_byid(parm->datatype);
			print_string(PRINT_ANY, "containertype", "    container type %s\n",
				     type->name);
		}
		if (parm->flags & P4TC_REGISTER_FLAGS_STARTBIT)
			print_uint(PRINT_ANY, "startbit", "    startbit %u\n",
				   parm->startbit);
		if (parm->flags & P4TC_REGISTER_FLAGS_ENDBIT)
			print_uint(PRINT_ANY, "endbit", "    endbit %u\n",
				   parm->endbit);
		if (parm->flags & P4TC_REGISTER_FLAGS_NUMELEMS)
			print_uint(PRINT_ANY, "numelems", "    number of elements %u\n",
				   parm->num_elems);

		print_register_template_value(tb[P4TC_REGISTER_VALUE], parm,
					      type, name, f);
	}

	return 0;
}

static int print_hdrfield(struct rtattr *tb, __u32 parser_id,
			   __u32 hdrfield_id, FILE *f)
{
	struct rtattr *tb_nest[P4TC_HDRFIELD_MAX + 1];
	struct p4tc_header_field_ty *hdr_ty;

	parse_rtattr_nested(tb_nest, P4TC_HDRFIELD_MAX, tb);

	if (parser_id)
		print_uint(PRINT_ANY, "parserid", "parserid %u\n",
			   parser_id);

	if (hdrfield_id)
		print_uint(PRINT_ANY, "hdrfieldid", "hdrfieldid %u\n",
			   hdrfield_id);

	if (tb_nest[P4TC_HDRFIELD_DATA]) {
		struct p4_type_s *type;

		hdr_ty = RTA_DATA(tb_nest[P4TC_HDRFIELD_DATA]);

		type = get_p4type_byid(hdr_ty->datatype);
		print_string(PRINT_ANY, "containertype", "container type %s\n",
			     type->name);
		print_uint(PRINT_ANY, "startbit", "startbit %u\n",
			   hdr_ty->startbit);
		print_uint(PRINT_ANY, "endbit", "endbit %u\n",
			   hdr_ty->endbit);
	}

	if (tb_nest[P4TC_HDRFIELD_NAME]) {
		const char *hdrfieldname;

		hdrfieldname = RTA_DATA(tb_nest[P4TC_HDRFIELD_NAME]);

		print_string(PRINT_ANY, "hdrfieldname", "Header field name %s\n",
			     hdrfieldname);
	}

	return 0;
}

static int print_p4_key(struct rtattr *nla, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct rtattr *tb_key[P4TC_TKEY_MAX + 1];

	open_json_object("key");
	parse_rtattr_nested(tb_key, P4TC_TKEY_MAX, nla);

	print_string(PRINT_FP, NULL, "    Key Action:\n", NULL);
	if (tb_key[P4TC_KEY_ACT]) {
		print_nl();
		tc_print_action(fp, tb_key[P4TC_KEY_ACT], 0);
	}
	print_nl();
	close_json_object();
	print_nl();

	return 0;
}

int p4tc_print_permissions(const char *prefix, __u16 *passed_permissions,
			   const char *suffix, FILE *f)
{
	char permissions[11] = {0};
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
		}
	}

	print_string(PRINT_FP, NULL, "%s", prefix);
	print_string(PRINT_ANY, "permissions", "permissions %s", permissions);
	print_string(PRINT_FP, NULL, "%s", suffix);

	return 0;
}

static int p4tc_print_table_default_action(struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_TABLE_DEFAULT_MAX + 1];

	parse_rtattr_nested(tb, P4TC_TABLE_DEFAULT_MAX, arg);

	tc_print_action(f, tb[P4TC_TABLE_DEFAULT_ACTION], 1);

	if (tb[P4TC_TABLE_DEFAULT_PERMISSIONS]) {
		__u16 *permissions;

		permissions = RTA_DATA(tb[P4TC_TABLE_DEFAULT_PERMISSIONS]);
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

static int p4tc_print_table(struct nlmsghdr *n, struct p4_tc_pipeline *pipe,
			    struct rtattr *arg, __u32 tbl_id, FILE *f)
{
	struct table *table = NULL;
	struct rtattr *tb[P4TC_TABLE_MAX + 1];

	parse_rtattr_nested(tb, P4TC_TABLE_MAX, arg);

	if (tbl_id) {
		print_uint(PRINT_ANY, "tblid", "    table id %u", tbl_id);
		print_nl();
	}

	if (tb[P4TC_TABLE_NAME])
		print_string(PRINT_ANY, "tname", "    table name %s\n",
			     RTA_DATA(tb[P4TC_TABLE_NAME]));

	if (tb[P4TC_TABLE_INFO]) {
		struct p4tc_table_parm *parm;

		parm = RTA_DATA(tb[P4TC_TABLE_INFO]);

		print_uint(PRINT_ANY, "keysz", "    key_sz %u\n",
			   parm->tbl_keysz);
		print_uint(PRINT_ANY, "max_entries", "    max entries %u\n",
			   parm->tbl_max_entries);
		print_uint(PRINT_ANY, "masks", "    masks %u\n",
			   parm->tbl_max_masks);
		print_uint(PRINT_ANY, "entries", "    table entries %u\n",
			   parm->tbl_num_entries);
		p4tc_print_permissions("    ", &parm->tbl_permissions, "\n", f);

		print_nl();
	}

	if (tb[P4TC_TABLE_KEY])
		print_p4_key(tb[P4TC_TABLE_KEY], tb[P4TC_TABLE_KEY]);

	if (tb[P4TC_TABLE_PREACTIONS]) {
		print_string(PRINT_FP, NULL,
			     "    preactions:\n", NULL);
		open_json_object("preactions");
		print_nl();
		tc_print_action(f, tb[P4TC_TABLE_PREACTIONS], 0);
		print_nl();
		close_json_object();
	}

	if (tb[P4TC_TABLE_POSTACTIONS]) {
		print_string(PRINT_FP, NULL,
			     "    postactions:\n", NULL);
		open_json_object("postactions");
		print_nl();
		tc_print_action(f, tb[P4TC_TABLE_POSTACTIONS], 0);
		print_nl();
		close_json_object();
	}

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

	if (tb[P4TC_TABLE_OPT_ENTRY]) {
		struct rtattr *tb_nest[P4TC_MAX + 1];

		if (tbl_id) {
			if (pipe) {
				table = p4tc_find_table_byid(pipe, tbl_id);
				if (!table) {
					fprintf(stderr, "Unable to find table id %d\n",
						tbl_id);
					return -1;
				}
			}
		}

		parse_rtattr_nested(tb_nest, P4TC_MAX,
				    tb[P4TC_TABLE_OPT_ENTRY]);
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
			RTA_PAYLOAD(RTA_LENGTH(tb[P4TC_ACT_NAME])));
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

	if (tb[P4TC_ACT_CMDS_LIST])
		p4tc_print_cmds(f, &au, tb[P4TC_ACT_CMDS_LIST]);

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

static int print_hdrfield_flush(struct nlmsghdr *n,
				struct rtattr *cnt_attr,
				FILE *f)
{
	const __u32 *cnt = RTA_DATA(cnt_attr);

	print_uint(PRINT_ANY, "count", "    header field flush count %u",
		   *cnt);
	print_nl();

	return 0;
}

static int print_metadata_type(struct nlmsghdr *n,
			       struct p4tc_meta_size_params *sz_params,
			       FILE *f)
{
	const __u16 sz = sz_params->endbit - sz_params->startbit + 1;

	switch (sz_params->datatype) {
	case P4T_U8:
	case P4T_U16:
	case P4T_U32:
	case P4T_U64:
	case P4T_U128:
		print_string(PRINT_ANY, "mtype", "    metadata type %s",
			     "bit");
		break;
	case P4T_S8:
	case P4T_S16:
	case P4T_S32:
	case P4T_S64:
	case P4T_S128:
		print_string(PRINT_ANY, "mtype", "    metadata type %s",
			     "int");
		break;
	case P4T_STRING:
		print_string(PRINT_ANY, "mtype", "    metadata type %s",
			     "strn");
		break;
	case P4T_NUL_STRING:
		print_string(PRINT_ANY, "mtype", "    metadata type %s",
			     "nstrn");
		break;
	}

	print_nl();
	print_uint(PRINT_ANY, "msize", "    metadata size %u", sz);

	return 0;
}

static int print_metadata(struct nlmsghdr *n, struct rtattr *arg, __u32 mid,
			  FILE *f)
{
	struct rtattr *tb[P4TC_META_MAX + 1];

	parse_rtattr_nested(tb, P4TC_META_MAX, arg);
	if (mid) {
		print_uint(PRINT_ANY, "mid", "    metadata id %u", mid);
		print_nl();
	}

	if (tb[P4TC_META_NAME]) {
		const char *name = RTA_DATA(tb[P4TC_META_NAME]);

		print_string(PRINT_ANY, "mname", "    metadata name %s", name);
		print_nl();
	}

	if (tb[P4TC_META_SIZE]) {
		struct p4tc_meta_size_params *sz_params;

		sz_params = RTA_DATA(tb[P4TC_META_SIZE]);
		print_metadata_type(n, sz_params, f);
	}
	print_nl();

	return 0;
}

static int print_metadata_flush(struct nlmsghdr *n, struct rtattr *cnt_attr,
				FILE *F)
{
	const __u32 *cnt = RTA_DATA(cnt_attr);

	print_uint(PRINT_ANY, "mcount", "    metadata flush count %u", *cnt);
	print_nl();

	return 0;
}

static int print_pipeline(struct nlmsghdr *n, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[P4TC_PIPELINE_MAX + 1];

	parse_rtattr_nested(tb, P4TC_PIPELINE_MAX, arg);

	if (tb[P4TC_PIPELINE_MAXRULES]) {
		__u32 max_rules =
		    *((__u32 *) RTA_DATA(tb[P4TC_PIPELINE_MAXRULES]));
		print_uint(PRINT_ANY, "pmaxrules", "    max_rules %lu",
			   max_rules);
		print_nl();
	}

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

	if (tb[P4TC_PIPELINE_PREACTIONS]) {
		print_string(PRINT_FP, NULL, "    preactions:", NULL);
		open_json_object("preactions");
		tc_print_action(f, tb[P4TC_PIPELINE_PREACTIONS], 0);
		print_nl();
		close_json_object();
	}

	if (tb[P4TC_PIPELINE_POSTACTIONS]) {
		print_string(PRINT_FP, NULL, "    postactions:", NULL);
		open_json_object("postactions");
		tc_print_action(f, tb[P4TC_PIPELINE_POSTACTIONS], 0);
		print_nl();
		close_json_object();
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

static int print_p4tmpl_1(struct nlmsghdr *n, struct p4_tc_pipeline *pipe,
			  __u16 cmd, struct rtattr *arg,
			  struct p4tcmsg *t, FILE *f)
{
	struct rtattr *tb[P4TC_MAX + 1];
	__u32 obj = t->obj;
	__u32 *ids;

	parse_rtattr_nested(tb, P4TC_MAX, arg);

	switch (obj) {
	case P4TC_OBJ_PIPELINE:
		if (cmd == RTM_P4TC_TMPL_GET && (n->nlmsg_flags & NLM_F_ROOT))
			print_pipeline_dump_1(n, tb[P4TC_PARAMS], f);
		else
			print_pipeline(n, f, tb[P4TC_PARAMS]);
		break;
	case P4TC_OBJ_META:
		if (cmd == RTM_P4TC_TMPL_DEL && (n->nlmsg_flags & NLM_F_ROOT))
			print_metadata_flush(n, tb[P4TC_COUNT], f);
		else {
			if (tb[P4TC_PATH]) {
				ids = RTA_DATA(tb[P4TC_PATH]);
				print_metadata(n, tb[P4TC_PARAMS], ids[0], f);
			} else {
				print_metadata(n, tb[P4TC_PARAMS], 0, f);
			}
		}
		break;
	case P4TC_OBJ_TABLE:
		if (cmd == RTM_P4TC_TMPL_DEL && (n->nlmsg_flags & NLM_F_ROOT))
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
	case P4TC_OBJ_HDR_FIELD:
		ids = RTA_DATA(tb[P4TC_PATH]);
		if (cmd == RTM_P4TC_TMPL_DEL && (n->nlmsg_flags & NLM_F_ROOT))
			print_hdrfield_flush(n, tb[P4TC_COUNT], f);
		else
			print_hdrfield(tb[P4TC_PARAMS], ids[0], ids[1], f);
		break;
	case P4TC_OBJ_ACT:
		ids = RTA_DATA(tb[P4TC_PATH]);
		if (cmd == RTM_P4TC_TMPL_DEL && (n->nlmsg_flags & NLM_F_ROOT))
			print_action_template_flush(n, tb[P4TC_COUNT], f);
		else {
			if (tb[P4TC_PATH])
				print_action_template(n, tb[P4TC_PARAMS],
						      ids[0], f);
			else
				print_action_template(n, tb[P4TC_PARAMS], 0, f);
		}
		break;
	case P4TC_OBJ_REGISTER:
		ids = RTA_DATA(tb[P4TC_PATH]);
		if (cmd == RTM_P4TC_TMPL_DEL && (n->nlmsg_flags & NLM_F_ROOT))
			print_register_flush(n, tb[P4TC_COUNT], f);
		else {
			if (tb[P4TC_PATH])
				print_register_template(n, tb[P4TC_PARAMS],
							ids[0], f);
			else
				print_register_template(n, tb[P4TC_PARAMS], 0,
							f);
		}
		break;
	default:
		break;
	}

	return 0;
}

#define TMPL_ARRAY_IS_EMPTY(tb) (!(tb[TMPL_ARRAY_START_IDX]))

static int print_p4tmpl_array(struct nlmsghdr *n, struct p4_tc_pipeline *pipe,
			      __u16 cmd, struct rtattr *nest, struct p4tcmsg *t,
			      void *arg)
{
	int ret = 0;
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, nest);
	if (TMPL_ARRAY_IS_EMPTY(tb))
		return 0;

	open_json_array(PRINT_JSON, "templates");
	for (i = TMPL_ARRAY_START_IDX; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		open_json_object(NULL);
		print_p4tmpl_1(n, pipe, cmd, tb[i], t, (FILE *)arg);
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);

	return ret;
}

int print_p4tmpl(struct nlmsghdr *n, void *arg)
{
	struct p4_tc_pipeline *pipe = NULL;
	struct rtattr *tb[P4TC_ROOT_MAX + 1];
	struct p4tcmsg *t = NLMSG_DATA(n);
	int len;

	len = n->nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*t));

	open_json_object(NULL);
	switch (n->nlmsg_type) {
	case RTM_P4TC_TMPL_CREATE:
		if (n->nlmsg_flags & NLM_F_REPLACE)
			print_bool(PRINT_ANY, "replaced", "replaced ",
				   true);
		else
			print_bool(PRINT_ANY, "created", "created ",
				   true);
		break;
	case RTM_P4TC_TMPL_DEL:
		print_bool(PRINT_ANY, "deleted", "deleted ", true);
		break;
	}

	parse_rtattr_flags(tb, P4TC_ROOT_MAX, P4TC_RTA(t), len, NLA_F_NESTED);

	switch (t->obj) {
	case P4TC_OBJ_PIPELINE:
		print_string(PRINT_ANY, "obj", "templates obj type %s\n",
			     "pipeline");
		break;
	case P4TC_OBJ_META:
		print_string(PRINT_ANY, "obj", "templates obj type %s\n",
			     "metadata");
		break;
	case P4TC_OBJ_TABLE:
		print_string(PRINT_ANY, "obj", "templates obj type %s\n",
			     "table");
		break;
	case P4TC_OBJ_ACT:
		print_string(PRINT_ANY, "obj", "template obj type %s\n",
			     "action template");
		break;
	case P4TC_OBJ_REGISTER:
		print_string(PRINT_ANY, "obj", "template obj type %s\n",
			     "register");
		break;
	}

	if (tb[P4TC_ROOT_PNAME]) {
		char *pname = RTA_DATA(tb[P4TC_ROOT_PNAME]);

		pipe = p4_tc_import_json(pname);

		print_string(PRINT_ANY, "pname", "pipeline name %s", pname);
		print_nl();
	}

	if (t->pipeid) {
		print_uint(PRINT_ANY, "pipeid", "pipeline id %u", t->pipeid);
		print_nl();
	}
	close_json_object();

	if (tb[P4TC_ROOT]) {
		open_json_object(NULL);
		print_p4tmpl_array(n, pipe, n->nlmsg_type, tb[P4TC_ROOT], t,
				   arg);
		close_json_object();
	}

	return 0;
}

static int parse_register_value(char *value_path,
				struct p4tc_u_register *parms,
				struct p4_type_value *val)
{
	char *p4tcpath[MAX_PATH_COMPONENTS] = {0};
	int ret = 0, base = 10;
	char *type_name, *value_arg;
	struct p4_type_s *type;
	__u32 bitsz;

	parse_path(value_path, p4tcpath, ".");

	if (strcmp(p4tcpath[0], "constant")) {
		fprintf(stderr, "value must be constant\n");
		return -1;
	}

	type_name = p4tcpath[1];
	type = get_p4type_byarg(type_name, &bitsz);
	if (!type) {
		fprintf(stderr, "Invalid type %s\n", type_name);
		return -1;
	}
	parms->datatype = type->containid;
	parms->startbit = 0;
	parms->endbit = bitsz - 1;
	parms->flags |= P4TC_REGISTER_FLAGS_STARTBIT;
	parms->flags |= P4TC_REGISTER_FLAGS_ENDBIT;

	if (bitsz > 64) {
		fprintf(stderr,
			"Unable to parse argument with more than 64 bits\n");
		return -1;
	}

	val->value = calloc(1, type->bitsz >> 3);
	if (!val->value) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}
	val->mask = calloc(1, type->bitsz >> 3);
	if (!val->mask) {
		fprintf(stderr, "Out of memory\n");
		free(val->value);
		return -1;
	}

	value_arg = p4tcpath[2];
	if (strnlen(value_arg, 2) == 2 && strncmp(value_arg, "0x", 2) == 0)
		base = 16;

	val->bitsz = bitsz;
	if (type->parse_p4t(val, value_arg, base) < 0)
		ret = -1;

	return ret;
}

static int parse_register_data_type(const char *type_arg,
				    struct p4tc_u_register *parms)
{
	struct p4_type_s *type;
	__u32 bitsz;

	type = get_p4type_byarg(type_arg, &bitsz);
	if (!type)
		return -1;

	parms->datatype = type->containid;
	parms->startbit = 0;
	parms->endbit = bitsz - 1;
	parms->flags |= P4TC_REGISTER_FLAGS_DATATYPE;
	parms->flags |= P4TC_REGISTER_FLAGS_STARTBIT;
	parms->flags |= P4TC_REGISTER_FLAGS_ENDBIT;

	return 0;
}

static int parse_register_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			       char *p4tcpath[], int cmd, unsigned int *flags)
{
	char full_regname[REGISTERNAMSIZ] = {0};
	struct p4tc_u_register parms = {0};
	struct p4_type_value val = {0};
	struct rtattr *count = NULL;
	struct rtattr *nest = NULL;
	bool parsed_value = false;
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 regid = 0;
	__u32 pipeid = 0;
	int ret = 0;
	char *regname;

	while (argc > 0) {
		if (cmd == RTM_P4TC_TMPL_CREATE) {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "regid") == 0) {
				NEXT_ARG();
				if (get_u32(&regid, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "type") == 0) {
				NEXT_ARG();
				if (parse_register_data_type(*argv, &parms) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "numelems") == 0) {
				NEXT_ARG();
				if (get_u32(&parms.num_elems, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
				parms.flags |= P4TC_REGISTER_FLAGS_NUMELEMS;
			} else if (strcmp(*argv, "index") == 0) {
				NEXT_ARG();
				if (get_u32(&parms.index, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
				parms.flags |= P4TC_REGISTER_FLAGS_INDEX;
			} else if (strcmp(*argv, "value") == 0) {
				NEXT_ARG();
				if (parse_register_value(*argv, &parms, &val) < 0) {
					ret = -1;
					goto out;
				}
				parsed_value = true;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				ret = -1;
				goto out;
			}
		} else {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "regid") == 0) {
				NEXT_ARG();
				if (get_u32(&regid, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "index") == 0) {
				NEXT_ARG();
				if (get_u32(&parms.index, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
				parms.flags |= P4TC_REGISTER_FLAGS_INDEX;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				ret = -1;
				goto out;
			}
		}

		argv++;
		argc--;
	}

	regname = p4tcpath[PATH_REGNAME_IDX];

	if (regname)
		ret = try_strncpy(full_regname, regname, REGISTERNAMSIZ);

	if (ret < 0) {
		fprintf(stderr, "register name too long\n");
		ret = -1;
		goto out;
	}

	count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
	if (!regname && !regid)
		*flags |= NLM_F_ROOT;

	if (regid)
		addattr32(n, MAX_MSG, P4TC_PATH, regid);

	if ((parms.flags & P4TC_REGISTER_FLAGS_DATATYPE) ||
	    parms.flags & P4TC_REGISTER_FLAGS_NUMELEMS ||
	    parms.flags & P4TC_REGISTER_FLAGS_INDEX || parsed_value ||
	    !STR_IS_EMPTY(full_regname))
		nest = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

	if (!STR_IS_EMPTY(full_regname))
		addattrstrz(n, MAX_MSG, P4TC_REGISTER_NAME, full_regname);

	if (parsed_value) {
		struct p4_type_s *type;
		size_t container_size;

		if (!(parms.flags & P4TC_REGISTER_FLAGS_INDEX)) {
			fprintf(stderr,
				"Must specify index if specifying value");
			ret = -1;
			goto out;
		}

		type = get_p4type_byid(parms.datatype);
		container_size = type->bitsz >> 3;
		addattr_l(n, MAX_MSG, P4TC_REGISTER_VALUE, val.value,
			  container_size);
	}

	if ((parms.flags & P4TC_REGISTER_FLAGS_DATATYPE) ||
	    parms.flags & P4TC_REGISTER_FLAGS_NUMELEMS ||
	    parms.flags & P4TC_REGISTER_FLAGS_INDEX)
		addattr_l(n, MAX_MSG, P4TC_REGISTER_INFO, &parms,
			  sizeof(parms));

	if (nest)
		addattr_nest_end(n, nest);

	addattr_nest_end(n, count);

	ret = pipeid;

out:
	*argc_p = argc;
	*argv_p = argv;
	free(val.value);
	free(val.mask);

	return ret;
}

static int parse_action_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			     char *p4tcpath[], int cmd, unsigned int *flags)
{
	char full_actname[ACTNAMSIZ] = {0};
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 pipeid = 0, actid = 0;
	struct action_util a = {0};
	int ret = 0, ins_cnt = 0;
	char *pname, *actname, *cbname;
	struct rtattr *count;
	struct rtattr *tail;

	discover_actions();

	pname = p4tcpath[PATH_PNAME_IDX];
	cbname = p4tcpath[PATH_CBNAME_IDX];
	actname = p4tcpath[PATH_ANAME_IDX];

	if (cbname && actname)
		ret = concat_cb_name(full_actname, cbname, actname, ACTNAMSIZ);
	else if (cbname)
		ret = try_strncpy(full_actname, cbname, ACTNAMSIZ);

	if (ret < 0) {
		fprintf(stderr, "Action name too long\n");
		return -1;
	}

	if (snprintf(a.id, ACTNAMSIZ, "%s/%s", pname, full_actname) == ACTNAMSIZ) {
		fprintf(stderr, "Action name too long\n");
		return -1;
	}

	count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
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
		} else if (strcmp(*argv, "cmd") == 0) {
			ins_cnt = p4tc_parse_cmds(&a, &argc, &argv);
			if (ins_cnt < 0)
				return -1;
		} else {
			if (parse_dyna(&argc, &argv, false, pname, full_actname, n) < 0)
				return -1;
			if (argc && strcmp(*argv, "cmd") == 0)
				continue;
		}
		argv++;
		argc--;
	}
	if (!STR_IS_EMPTY(full_actname))
		addattrstrz(n, MAX_MSG, P4TC_ACT_NAME, full_actname);

	if (p4tc_add_cmds(n, ins_cnt, P4TC_ACT_CMDS_LIST) < 0)
		return -1;

	addattr_nest_end(n, tail);
	if (actid)
		addattr32(n, MAX_MSG, P4TC_PATH, actid);
	if (!actid && !cbname && !actname)
		*flags |= NLM_F_ROOT;
	addattr_nest_end(n, count);

	ret = pipeid;

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

static int parse_hdrfield_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			       char *p4tcpath[], int cmd, unsigned int *flags)
{
	__u32 pipeid = 0, parser_id = 0, hdrfield_id = 0;
	struct p4tc_header_field_ty hdr_ty = {0};
	__u32 bitsz = 0;
	struct rtattr *count = NULL;
	struct p4_type_s *t = NULL;
	char **argv = *argv_p;
	int argc = *argc_p;
	/* Parser instance id + header field id */
	__u32 ids[2] = {0};
	char *parser_name, *hdrname, *fieldname;
	char full_hdr_name[HDRFIELDNAMSIZ];
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "pipeid") == 0) {
			NEXT_ARG();
			if (get_u32(&pipeid, *argv, 10) < 0)
				return -1;
		} else if (strcmp(*argv, "parserid") == 0) {
			NEXT_ARG();
			if (get_u32(&parser_id, *argv, 10) < 0)
				return -1;
		} else if (strcmp(*argv, "hdrfieldid") == 0) {
			NEXT_ARG();
			if (get_u32(&hdrfield_id, *argv, 10) < 0)
				return -1;
		} else if (strcmp(*argv, "type") == 0) {
			NEXT_ARG();
			t = get_p4type_byarg(*argv, &bitsz);
		}

		argv++;
		argc--;
	}

	parser_name = p4tcpath[PATH_PARSERNAME_IDX];
	hdrname = p4tcpath[PATH_HDRNAME_IDX];
	fieldname = p4tcpath[PATH_HDRFIELDNAME_IDX];

	if (cmd == RTM_P4TC_TMPL_CREATE) {
		if (!t) {
			fprintf(stderr, "Must specify hdrfield type\n");
			return -1;
		}

		hdr_ty.startbit = 0;
		hdr_ty.endbit = bitsz - 1;
		hdr_ty.datatype = t->containid;
	}

	if (!hdrfield_id && !(hdrname && fieldname) && cmd != RTM_P4TC_TMPL_CREATE) {
		*flags |= NLM_F_ROOT;
	}

	/* Always add count nest unless it's a dump */
	if (!((*flags & NLM_F_ROOT) && cmd == RTM_P4TC_TMPL_GET))
		count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);

	if (parser_id)
		ids[0] = parser_id;
	if (hdrfield_id)
		ids[1] = hdrfield_id;
	addattr_l(n, MAX_MSG, P4TC_PATH, ids, sizeof(ids));

	tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

	if (parser_name)
		addattrstrz(n, MAX_MSG, P4TC_HDRFIELD_PARSER_NAME,
			    parser_name);

	if (cmd == RTM_P4TC_TMPL_CREATE) {
		addattr_l(n, MAX_MSG, P4TC_HDRFIELD_DATA, &hdr_ty,
			  sizeof(hdr_ty));
	}
	if (fieldname) {
		concat_cb_name(full_hdr_name, hdrname, fieldname,
			       HDRFIELDNAMSIZ);
		addattrstrz(n, MAX_MSG, P4TC_HDRFIELD_NAME, full_hdr_name);
	}
	addattr_nest_end(n, tail);

	if (count)
		addattr_nest_end(n, count);

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

static int parse_table_key(struct nlmsghdr *n,  int *argc_p, char ***argv_p)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret = 0;

	argc -= 1;
	argv += 1;

	while (argc > 0) {
		if (matches(*argv, "action") == 0) {
			if (parse_action(&argc, &argv, P4TC_KEY_ACT | NLA_F_NESTED, n)) {
				fprintf(stderr, "Illegal action\n");
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "postactions") == 0) {
			ret = 0;
			goto out;
		} else if (strcmp(*argv, "preactions") == 0) {
			ret = 0;
			goto out;
		} else {
			ret = -1;
			goto out;
		}
		argv++;
		argc--;
	}

out:
	*argc_p = argc;
	*argv_p = argv;

	return ret;
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

static int parse_table_default_action(int *argc_p, char ***argv_p,
                                     struct nlmsghdr *n, __u32 attr_id)
{
       struct rtattr *tail;
       char **argv = *argv_p;
       int argc = *argc_p;
       __u16 permissions;

       tail = addattr_nest(n, MAX_MSG, attr_id | NLA_F_NESTED);
       while (argc > 0) {
               if (strcmp(*argv, "action") == 0) {
                       if (parse_action(&argc, &argv,
                                        P4TC_TABLE_DEFAULT_ACTION | NLA_F_NESTED, n)) {
                               fprintf(stderr, "Illegal action\n");
                               return -1;
                       }
               } else if (strcmp(*argv, "permissions") == 0) {
                       NEXT_ARG();
                       if (get_u16(&permissions, *argv, 16) < 0)
                               return -1;
                       addattr16(n, MAX_MSG, P4TC_TABLE_DEFAULT_PERMISSIONS,
                                 permissions);
               }
               NEXT_ARG_FWD();
       }
       addattr_nest_end(n, tail);

       *argc_p = argc;
       *argv_p = argv;

       return 0;
}

static int parse_table_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			    char *p4tcpath[], int cmd, unsigned int *flags)
{
	struct p4tc_table_parm table = {0};
	char full_tblname[TABLENAMSIZ] = {0};
	struct rtattr *count = NULL;
	struct rtattr *tail2 = NULL;
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 tbl_id = 0;
	__u32 pipeid = 0;
	int ret = 0;
	char *pname, *cbname, *tblname;

	pname = p4tcpath[PATH_PNAME_IDX];
	cbname = p4tcpath[PATH_CBNAME_IDX];
	tblname = p4tcpath[PATH_TBLNAME_IDX];

	if (cmd != RTM_P4TC_TMPL_GET) {
		count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
		tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);
	}

	if (cbname && tblname) {
		ret = concat_cb_name(full_tblname, cbname, tblname,
				     TABLENAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "table name too long\n");
			return -1;
		}
	}

	while (argc > 0) {
		if (cmd == RTM_P4TC_TMPL_CREATE) {
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
				if (get_u32(&table.tbl_keysz, *argv, 10) < 0)
					return -1;
				table.tbl_flags |= P4TC_TABLE_FLAGS_KEYSZ;
			} else if (strcmp(*argv, "tentries") == 0) {
				NEXT_ARG();
				if (get_u32(&table.tbl_max_entries, *argv, 10) < 0)
					return -1;
				table.tbl_flags |= P4TC_TABLE_FLAGS_MAX_ENTRIES;
			} else if (strcmp(*argv, "nummasks") == 0) {
				NEXT_ARG();
				if (get_u32(&table.tbl_max_masks, *argv, 10) < 0)
					return -1;
				table.tbl_flags |= P4TC_TABLE_FLAGS_MAX_MASKS;
			} else if (strcmp(*argv, "type") == 0) {
				NEXT_ARG();
				if (strcmp(*argv, "lpm") == 0) {
					table.tbl_type = P4TC_TABLE_TYPE_LPM;
				} else if (strcmp(*argv, "exact") == 0) {
					table.tbl_type = P4TC_TABLE_TYPE_EXACT;
				} else if (strcmp(*argv, "ternary") == 0) {
					table.tbl_type = P4TC_TABLE_TYPE_TERNARY;
				} else {
					fprintf(stderr, "Uknown table type %s\n", *argv);
					return -1;
				}
				table.tbl_flags |= P4TC_TABLE_FLAGS_TYPE;
			} else if (strcmp(*argv, "key") == 0) {
				if (tail2) {
					fprintf(stderr,
						"Can't specify table key twitce\n");
					return -1;
				}
				tail2 = addattr_nest(n, MAX_MSG,
						     P4TC_TABLE_KEY | NLA_F_NESTED);
				ret = parse_table_key(n, &argc, &argv);
				if (ret < 0)
					goto out;
				else {
					addattr_nest_end(n, tail2);
					continue;
				}
			} else if (strcmp(*argv, "preactions") == 0) {
				argv++;
				argc--;
				if (parse_action(&argc, &argv,
						 P4TC_TABLE_PREACTIONS | NLA_F_NESTED, n)) {
					fprintf(stderr, "Illegal action\n");
					return -1;
				}
				continue;
			} else if (strcmp(*argv, "postactions") == 0) {
				argv++;
				argc--;
				if (parse_action(&argc, &argv,
						 P4TC_TABLE_POSTACTIONS | NLA_F_NESTED, n)) {
					fprintf(stderr, "Illegal action\n");
					return -1;
				}
				continue;
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
				if (get_u16(&table.tbl_permissions, *argv, 16) < 0)
					return -1;
				table.tbl_flags |= P4TC_TABLE_FLAGS_PERMISSIONS;
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
						       P4TC_TABLE_OPT_ENTRY | NLA_F_NESTED);

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
			} else if (cmd == RTM_P4TC_TMPL_DEL &&
				   strcmp(*argv, "default_hit_action") == 0) {
				struct rtattr *nest_hit_act;

				argv++;
				argc--;
				nest_hit_act = addattr_nest(n, MAX_MSG,
							    P4TC_TABLE_DEFAULT_HIT | NLA_F_NESTED);
				addattr_nest_end(n, nest_hit_act);
				continue;
			} else if (cmd == RTM_P4TC_TMPL_DEL &&
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

	if (!cbname && !tblname && !tbl_id) {
		*flags |= NLM_F_ROOT;
	} else if (cmd == RTM_P4TC_TMPL_GET) {
		count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
		tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);
	}

	if (cmd == RTM_P4TC_TMPL_CREATE && table.tbl_flags)
		addattr_l(n, MAX_MSG, P4TC_TABLE_INFO, &table,
			  sizeof(table));

	ret = 0;
	if (!STR_IS_EMPTY(full_tblname))
		addattrstrz(n, MAX_MSG, P4TC_TABLE_NAME, full_tblname);

	if (tail)
		addattr_nest_end(n, tail);

	if (tbl_id)
		addattr32(n, MAX_MSG, P4TC_PATH, tbl_id);

	if (count)
		addattr_nest_end(n, count);

out:
	*argc_p = argc;
	*argv_p = argv;

	if (ret < 0)
		return ret;
	return pipeid;
}

static int parse_meta_data_type(const char *type_arg,
				struct p4tc_meta_size_params *sz_params)
{
	struct p4_type_s *type;
	__u32 bitsz;

	type = get_p4type_byarg(type_arg, &bitsz);
	if (!type)
		return -1;

	sz_params->datatype = type->containid;
	sz_params->startbit = 0;
	sz_params->endbit = bitsz - 1;

	return 0;
}

#define P4TC_FLAGS_META_SIZE   0x1
#define P4TC_FLAGS_META_ID    0x2

static int parse_meta_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			   char *p4tcpath[], int cmd, unsigned int *flags)
{
	char full_mname[METANAMSIZ] = {0};
	struct rtattr *count = NULL;
	char **argv = *argv_p;
	__u8 meta_flags = 0;
	int argc = *argc_p;
	__u32 mid = 0;
	__u32 pipeid = 0;
	int ret = 0;
	struct p4tc_meta_size_params sz_params;
	char *cbname, *mname;
	struct rtattr *nest;

	while (argc > 0) {
		if (cmd == RTM_P4TC_TMPL_CREATE) {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "mid") == 0) {
				NEXT_ARG();
				if (get_u32(&mid, *argv, 10) < 0)
					return -1;

				meta_flags |= P4TC_FLAGS_META_ID;
			} else if (strcmp(*argv, "type") == 0) {
				NEXT_ARG();
				if (parse_meta_data_type(*argv, &sz_params) < 0)
					return -1;

				meta_flags |= P4TC_FLAGS_META_SIZE;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
		} else {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "mid") == 0) {
				NEXT_ARG();
				if (get_u32(&mid, *argv, 10) < 0)
					return -1;

				meta_flags |= P4TC_FLAGS_META_ID;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
		}

		argv++;
		argc--;
	}

	mname = p4tcpath[PATH_MNAME_IDX];
	cbname = p4tcpath[PATH_CBNAME_IDX];

	if (cbname && mname)
		ret = concat_cb_name(full_mname, cbname, mname, METANAMSIZ);
	else if (cbname)
		ret = try_strncpy(full_mname, cbname, METANAMSIZ);

	if (ret < 0) {
		fprintf(stderr, "metadata name too long\n");
		return -1;
	}

	count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
	if (!cbname && !mname && !mid)
		*flags |= NLM_F_ROOT;

	if (mid)
		addattr32(n, MAX_MSG, P4TC_PATH, mid);

	if (meta_flags & P4TC_FLAGS_META_SIZE || !STR_IS_EMPTY(full_mname)) {
		nest = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

		if (meta_flags & P4TC_FLAGS_META_SIZE)
			addattr_l(n, MAX_MSG, P4TC_META_SIZE, &sz_params,
				  sizeof(sz_params));
		if (!STR_IS_EMPTY(full_mname))
			addattrstrz(n, MAX_MSG, P4TC_META_NAME, full_mname);

		addattr_nest_end(n, nest);
	}
	addattr_nest_end(n, count);

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

static int parse_pipeline_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			       int cmd, unsigned int flags)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 pipeid = 0;
	struct rtattr *count;
	struct rtattr *nest;
	__u32 maxrules;
	__u16 numtables;

	if (cmd == RTM_P4TC_TMPL_CREATE) {
		count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
		nest = addattr_nest(n, MAX_MSG, P4TC_PARAMS | NLA_F_NESTED);

		while (argc > 0) {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "maxrules") == 0) {
				NEXT_ARG();
				if (get_u32(&maxrules, *argv, 10) < 0)
					return -1;

				addattr32(n, MAX_MSG, P4TC_PIPELINE_MAXRULES,
					  maxrules);
			} else if (strcmp(*argv, "numtables") == 0) {
				NEXT_ARG();
				if (get_u16(&numtables, *argv, 10) < 0)
					return -1;

				addattr16(n, MAX_MSG, P4TC_PIPELINE_NUMTABLES,
					  numtables);
			} else if (strcmp(*argv, "preactions") == 0) {
				argv++;
				argc--;
				if (parse_action(&argc, &argv,
						 P4TC_PIPELINE_PREACTIONS | NLA_F_NESTED, n)) {
					fprintf(stderr, "Illegal action\n");
					return -1;
				}
				continue;
			} else if (strcmp(*argv, "postactions") == 0) {
				argv++;
				argc--;
				if (parse_action(&argc, &argv,
						 P4TC_PIPELINE_POSTACTIONS | NLA_F_NESTED, n)) {
					fprintf(stderr, "Illegal action\n");
					return -1;
				}
				continue;
			} else if (strcmp(*argv, "state") == 0 && flags & NLM_F_REPLACE) {
				argv++;
				argc--;
				if (strcmp(*argv, "ready") == 0) {
					addattr8(n, MAX_MSG, P4TC_PIPELINE_STATE,
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
		addattr_nest_end(n, count);
	} else {
		count = addattr_nest(n, MAX_MSG, 1 | NLA_F_NESTED);
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
		addattr_nest_end(n, count);
	}

	if (cmd == RTM_P4TC_TMPL_CREATE) {
		addattr_nest_end(n, nest);
		addattr_nest_end(n, count);
	}

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
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
	case P4TC_OBJ_META:
		pipeid = parse_meta_data(&argc, &argv, &req.n, p4tcpath, cmd,
					 &flags);
		if (pipeid < 0)
			return -1;
		req.t.pipeid = pipeid;

		break;
	case P4TC_OBJ_TABLE:
		pipeid = parse_table_data(&argc, &argv, &req.n, p4tcpath, cmd,
					  &flags);
		if (pipeid < 0)
			return -1;
		req.t.pipeid = pipeid;

		break;
	case P4TC_OBJ_HDR_FIELD:
		pipeid = parse_hdrfield_data(&argc, &argv, &req.n, p4tcpath,
					     cmd, &flags);
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
	case P4TC_OBJ_REGISTER:
		pipeid = parse_register_data(&argc, &argv, &req.n, p4tcpath,
					     cmd, &flags);
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

	if (cmd == RTM_P4TC_TMPL_GET) {
		if (flags & NLM_F_ROOT) {
			int msg_size;

			msg_size = NLMSG_ALIGN(req.n.nlmsg_len) -
				NLMSG_ALIGN(sizeof(struct nlmsghdr));
			if (rtnl_dump_request(&rth, RTM_P4TC_TMPL_GET,
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
		if (rtnl_talk(&rth, &req.n, NULL) < 0) {
			fprintf(stderr, "We have an error talking to the kernel\n");
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
			ret = p4tmpl_cmd(RTM_P4TC_TMPL_CREATE,
					 NLM_F_EXCL | NLM_F_CREATE, &argc,
					 &argv);
		} else if (matches(*argv, "update") == 0) {
			ret = p4tmpl_cmd(RTM_P4TC_TMPL_CREATE, NLM_F_REPLACE,
					 &argc, &argv);
		} else if (matches(*argv, "delete") == 0) {
			ret = p4tmpl_cmd(RTM_P4TC_TMPL_DEL, 0, &argc, &argv);
		} else if (matches(*argv, "get") == 0) {
			ret = p4tmpl_cmd(RTM_P4TC_TMPL_GET, 0, &argc, &argv);
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
