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
#include <linux/tc_act/tc_metact.h>

#include "utils.h"
#include "tc_common.h"
#include "tc_util.h"
#include "p4tc_common.h"
#include "p4_types.h"
#include "p4tc_introspection.h"

static struct hlist_head kernel_metadata_list = {};

static struct p4_metat_s pktlen_meta = {
	.id = METACT_LMETA_PKTLEN,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "pktlen",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s datalen_meta = {
	.id = METACT_LMETA_DATALEN,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "datalen",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbmark_meta = {
	.id = METACT_LMETA_SKBMARK,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "skbmark",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s tcindex_meta = {
	.id = METACT_LMETA_TCINDEX,
	.containid = P4T_U16,
	.startbit = 0,
	.endbit = 15,
	.name = "tcindex",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbhash_meta = {
	.id = METACT_LMETA_SKBHASH,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "skbhash",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbprio_meta = {
	.id = METACT_LMETA_SKBPRIO,
	.containid = P4T_U32,
	.startbit = 0,
	.endbit = 31,
	.name = "skbprio",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s ifindex_meta = {
	.id = METACT_LMETA_IFINDEX,
	.containid = P4T_S32,
	.startbit = 0,
	.endbit = 31,
	.name = "ifindex",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s iif_meta = {
	.id = METACT_LMETA_SKBIIF,
	.containid = P4T_S32,
	.startbit = 0,
	.endbit = 31,
	.name = "iif",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s protocol_meta = {
	.id = METACT_LMETA_PROTOCOL,
	.containid = P4T_BE16,
	.startbit = 0,
	.endbit = 15,
	.name = "skbproto",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbptype_meta = {
	.id = METACT_LMETA_PKTYPE,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 2,
	.name = "skbptype",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbidf_meta = {
	.id = METACT_LMETA_IDF,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 0,
	.name = "skbidf",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbipsum_meta = {
	.id = METACT_LMETA_IPSUM,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 1,
	.name = "skbipsum",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbfclon_meta = {
	.id = METACT_LMETA_FCLONE,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 1,
	.name = "skbfclon",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbpeek_meta = {
	.id = METACT_LMETA_PEEKED,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 0,
	.name = "skbpeek",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skboook_meta = {
	.id = METACT_LMETA_OOOK,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 0,
	.name = "skboook",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s skbqmap_meta = {
	.id = METACT_LMETA_QMAP,
	.containid = P4T_U16,
	.startbit = 0,
	.endbit = 15,
	.name = "skbqmap",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s ptypeoff_meta = {
	.id = METACT_LMETA_PTYPEOFF,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 7,
	.name = "ptypeoff",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s cloneoff_meta = {
	.id = METACT_LMETA_CLONEOFF,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 7,
	.name = "cloneoff",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s direction_meta = {
	.id = METACT_LMETA_DIRECTION,
	.containid = P4T_U8,
	.startbit = 0,
	.endbit = 0,
	.name = "direction",
	.pipeid = 0,
	.pname = "kernel",
};

static struct p4_metat_s ptclnoff_meta = {
	.id = METACT_LMETA_PTCLNOFF,
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

static int try_strncpy(char *dest, const char *src, size_t max_len)
{
	if (strnlen(src, max_len) == max_len)
		return -1;

	strcpy(dest, src);

	return 0;
}

static void p4template_usage(void)
{
	fprintf(stderr,
		"usage: tc p4template create | update pipeline/pname [PIPEID] OPTS\n"
		"       tc p4tempalte del | get pipeline/[pname] [PIPEID]\n"
		"Where:  OPTS := NUMTCLASSES PREACTIONS POSTACTIONS STATE\n"
		"	PIPEID := pipeid <32 bit pipeline id>\n"
		"	NUMTCLASSES := numtclasses <16 bit numtclasses>\n"
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

static int print_p4_key(struct rtattr *tb, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct rtattr *tb_nest[P4TC_MAXPARSE_KEYS + 1];
	int i;

	parse_rtattr_nested(tb_nest, P4TC_MAXPARSE_KEYS, tb);

	for (i = 1; i < P4TC_MAXPARSE_KEYS + 1 && tb_nest[i]; i++) {
		struct rtattr *tb_key[P4TC_MAXPARSE_KEYS + 1];

		open_json_object(NULL);
		parse_rtattr_nested(tb_key, P4TC_MAXPARSE_KEYS, tb_nest[i]);

		if (tb_key[P4TC_KEY_ID]) {
			const __u32 *id = RTA_DATA(tb_key[P4TC_KEY_ID]);

			print_uint(PRINT_ANY, "id", "    Key ID %u\n", *id);
		}

		print_string(PRINT_FP, NULL, "    Key Action:\n", NULL);
		if (tb_key[P4TC_KEY_ACT]) {
			print_nl();
			tc_print_action(fp, tb_key[P4TC_KEY_ACT], 0);
		}
		print_nl();
		close_json_object();
	}
	print_nl();

	return 0;
}

static int print_table_class(struct nlmsghdr *n, struct rtattr *arg,
			     __u32 tbc_id, FILE *f)
{
	struct rtattr *tb[P4TC_TCLASS_MAX + 1];

	parse_rtattr_nested(tb, P4TC_TCLASS_MAX, arg);

	if (tbc_id) {
		print_uint(PRINT_ANY, "tbcid", "    tclass id %u", tbc_id);
		print_nl();
	}

	if (tb[P4TC_TCLASS_NAME])
		print_string(PRINT_ANY, "tname", "    tclass name %s\n",
			     RTA_DATA(tb[P4TC_TCLASS_NAME]));

	if (tb[P4TC_TCLASS_INFO]) {
		struct p4tc_table_class_parm *parm;

		parm = RTA_DATA(tb[P4TC_TCLASS_INFO]);

		print_uint(PRINT_ANY, "keysz", "    key_sz %u\n",
			   parm->tbc_keysz);
		print_uint(PRINT_ANY, "count", "    count %u\n",
			   parm->tbc_count);
		print_uint(PRINT_ANY, "entries", "    entries %u\n",
			   parm->tbc_max_entries);
		print_uint(PRINT_ANY, "masks", "    masks %u\n",
			   parm->tbc_max_masks);
		print_uint(PRINT_ANY, "default_key", "    default key %u\n",
			   parm->tbc_default_key);

		print_nl();
	}

	if (tb[P4TC_TCLASS_KEYS]) {
		open_json_array(PRINT_JSON, "keys");
		print_p4_key(tb[P4TC_TCLASS_KEYS], arg);
		close_json_array(PRINT_JSON, NULL);
	}

	if (tb[P4TC_TCLASS_PREACTIONS]) {
		print_string(PRINT_FP, NULL,
			     "    preactions:\n", NULL);
		open_json_object("preactions");
		print_nl();
		tc_print_action(f, tb[P4TC_TCLASS_PREACTIONS], 0);
		print_nl();
		close_json_object();
	}

	if (tb[P4TC_TCLASS_POSTACTIONS]) {
		print_string(PRINT_FP, NULL,
			     "    postactions:\n", NULL);
		open_json_object("postactions");
		print_nl();
		tc_print_action(f, tb[P4TC_TCLASS_POSTACTIONS], 0);
		print_nl();
		close_json_object();
	}

	print_nl();

	return 0;
}

static int print_table_class_flush(struct nlmsghdr *n, struct rtattr *cnt_attr,
				   FILE *F)
{
	const __u32 *cnt = RTA_DATA(cnt_attr);

	print_uint(PRINT_ANY, "ttcount", "    table class flush count %u", *cnt);
	print_nl();

	return 0;
}

static int print_table_instance(struct nlmsghdr *n, struct rtattr *arg,
				__u32 tbc_id, __u32 ti_id, FILE *f)
{
	struct rtattr *tb[P4TC_TINST_MAX + 1];

	parse_rtattr_nested(tb, P4TC_TINST_MAX, arg);

	if (tbc_id) {
		print_uint(PRINT_ANY, "tbcid", "    table class id %u\n", tbc_id);
		print_nl();
	}

	if (ti_id) {
		print_uint(PRINT_ANY, "tiid", "    table instance id %u\n", ti_id);
		print_nl();
	}

	if (tb[P4TC_TINST_CLASS]) {
		const char *name = RTA_DATA(tb[P4TC_TINST_CLASS]);

		print_string(PRINT_ANY, "tbcname", "    table class name %s\n", name);
	}

	if (tb[P4TC_TINST_NAME]) {
		const char *name = RTA_DATA(tb[P4TC_TINST_NAME]);

		print_string(PRINT_ANY, "tiname", "    table instance name %s\n", name);
	}

	if (tb[P4TC_TINST_CUR_ENTRIES]) {
		const __u32 *entries = RTA_DATA(tb[P4TC_TINST_CUR_ENTRIES]);

		print_uint(PRINT_ANY, "entries", "    table instance entries %u\n",
			   *entries);
	}

	if (tb[P4TC_TINST_MAX_ENTRIES]) {
		const __u32 *entries = RTA_DATA(tb[P4TC_TINST_MAX_ENTRIES]);

		print_uint(PRINT_ANY, "maxentries", "    table instance max entries %u\n",
			   *entries);
	}

	return 0;
}

static int print_table_instance_flush(struct nlmsghdr *n,
				      struct rtattr *cnt_attr,
				      FILE *f)
{
	const __u32 *cnt = RTA_DATA(cnt_attr);

	print_uint(PRINT_ANY, "ticount", "    table instance flush count %u",
		   *cnt);
	print_nl();

	return 0;
}

static int print_action_template(struct nlmsghdr *n, struct rtattr *arg,
				 __u32 a_id, FILE *f)
{
	struct rtattr *tb[P4TC_ACT_MAX + 1];

	parse_rtattr_nested(tb, P4TC_ACT_MAX, arg);

	if (tb[P4TC_ACT_NAME]) {
		const char *name = RTA_DATA(tb[P4TC_ACT_NAME]);

		print_string(PRINT_ANY, "aname", "    template action name %s\n", name);
	}
	if (a_id)
		print_uint(PRINT_ANY, "actid", "    action id %u\n", a_id);

	if (tb[P4TC_ACT_PARMS]) {
		print_string(PRINT_FP, NULL, "\n\t params:\n", "");
		open_json_array(PRINT_JSON, "params");
		print_dyna_parms(tb[P4TC_ACT_PARMS], f);
		close_json_array(PRINT_JSON, NULL);
	}

	if (tb[P4TC_ACT_METACT_LIST])
		print_metact_cmds(f, tb[P4TC_ACT_METACT_LIST]);

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

	if (tb[P4TC_PIPELINE_NUMTCLASSES]) {
		__u16 num_tclasses =
		    *((__u16 *) RTA_DATA(tb[P4TC_PIPELINE_NUMTCLASSES]));
		print_uint(PRINT_ANY, "pnumtclasses", "    num_tclasses %u",
			   num_tclasses);
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

static int print_p4tmpl_1(struct nlmsghdr *n, __u16 cmd, struct rtattr *arg,
			  struct p4tcmsg *t, FILE *f)
{
	struct rtattr *tb[P4TC_MAX + 1];
	__u32 obj = t->obj;
	__u32 *ids;

	parse_rtattr_nested(tb, P4TC_MAX, arg);

	switch (obj) {
	case P4TC_OBJ_PIPELINE:
		if (cmd == RTM_GETP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
			print_pipeline_dump_1(n, tb[P4TC_PARAMS], f);
		else
			print_pipeline(n, f, tb[P4TC_PARAMS]);
		break;
	case P4TC_OBJ_META:
		if (cmd == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
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
	case P4TC_OBJ_TABLE_CLASS:
		if (cmd == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
			print_table_class_flush(n, tb[P4TC_COUNT], f);
		else {
			if (tb[P4TC_PATH]) {
				ids = RTA_DATA(tb[P4TC_PATH]);
				print_table_class(n, tb[P4TC_PARAMS], ids[0],
						  f);
			} else {
				print_table_class(n, tb[P4TC_PARAMS], 0, f);
			}
		}
		break;
	case P4TC_OBJ_TABLE_INST: {
		ids = RTA_DATA(tb[P4TC_PATH]);
		if (cmd == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
			print_table_instance_flush(n, tb[P4TC_COUNT], f);
		else {
			if (tb[P4TC_PATH])
				print_table_instance(n, tb[P4TC_PARAMS], ids[0],
						     ids[1], f);
			else
				print_table_instance(n, tb[P4TC_PARAMS], 0,
						     0, f);
		}
		break;
	}
	case P4TC_OBJ_HDR_FIELD:
		ids = RTA_DATA(tb[P4TC_PATH]);
		if (cmd == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
			print_hdrfield_flush(n, tb[P4TC_COUNT], f);
		else
			print_hdrfield(tb[P4TC_PARAMS], ids[0], ids[1], f);
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

static int print_p4tmpl_array(struct nlmsghdr *n, __u16 cmd,
			      struct rtattr *nest,
			      struct p4tcmsg *t, void *arg)
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
		print_p4tmpl_1(n, cmd, tb[i], t, (FILE *)arg);
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);

	return ret;
}

int print_p4tmpl(struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[P4TC_ROOT_MAX + 1];
	struct p4tcmsg *t = NLMSG_DATA(n);
	int len;

	len = n->nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*t));

	open_json_object(NULL);
	switch (n->nlmsg_type) {
	case RTM_NEWP4TEMPLATE:
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
	case P4TC_OBJ_META:
		print_string(PRINT_ANY, "obj", "templates obj type %s\n",
			     "metadata");
		break;
	case P4TC_OBJ_TABLE_CLASS:
		print_string(PRINT_ANY, "obj", "templates obj type %s\n",
			     "table class");
		break;
	case P4TC_OBJ_TABLE_INST:
		print_string(PRINT_ANY, "obj", "templates obj type %s\n",
			     "table instance");
		break;
	case P4TC_OBJ_ACT:
		print_string(PRINT_ANY, "obj", "template obj type %s\n",
			     "action template");
	}

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
		print_p4tmpl_array(n, n->nlmsg_type, tb[P4TC_ROOT], t, arg);
		close_json_object();
	}

	return 0;
}

#define PATH_SEPARATOR "/"

/* PATH SYNTAX: tc p4template objtype/pname/...  */
void parse_path(char *path, char **p4tcpath)
{
	int i = 0;
	char *component;

	component = strtok(path, PATH_SEPARATOR);
	while (component) {
		p4tcpath[i++] = component;
		component = strtok(NULL, PATH_SEPARATOR);
	}
}

#define MAX_OBJ_TYPE_NAME_LEN 32

int get_obj_type(const char *str_obj_type)
{
	if (!strcmp(str_obj_type, "pipeline"))
		return P4TC_OBJ_PIPELINE;
	else if (!strcmp(str_obj_type, "metadata"))
		return P4TC_OBJ_META;
	else if (!strcmp(str_obj_type, "tclass"))
		return P4TC_OBJ_TABLE_CLASS;
	else if (!strcmp(str_obj_type, "tinst"))
		return P4TC_OBJ_TABLE_INST;
	else if (!strcmp(str_obj_type, "hdrfield"))
		return P4TC_OBJ_HDR_FIELD;
	else if (!strcmp(str_obj_type, "action"))
		return P4TC_OBJ_ACT;
	else if (!strcmp(str_obj_type, "table"))
		return P4TC_OBJ_TABLE_ENTRY;

	return -1;
}

int concat_cb_name(char *full_name, const char *cbname,
			   const char *objname, size_t sz)
{
	return snprintf(full_name, sz, "%s/%s", cbname, objname) >= sz ? -1 : 0;
}

int fill_user_metadata(struct p4_metat_s metadata[])
{
	int num_metadata;
	int i;

	num_metadata = p4tc_get_metadata(metadata);
	if (num_metadata < 0)
		return -1;

	for (i = 0; i < num_metadata; i++)
		register_new_metadata(&metadata[i]);

	return 0;
}

static int parse_action_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			     char *p4tcpath[], int cmd, unsigned int *flags)
{
	char full_actname[ACTNAMSIZ] = {0};
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 pipeid = 0, actid = 0;
	int ret = 0, ins_cnt = 0;
	struct p4_metat_s metadata[32];
	char *pname, *actname, *cbname;
	struct action_util *a;
	struct rtattr *count;
	struct rtattr *tail;

	discover_actions();

	a = get_action_byid(TCA_ID_METACT);

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

	register_kernel_metadata();
	fill_user_metadata(metadata);

	count = addattr_nest(n, MAX_MSG, 1);
	tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS);
	while (argc > 0) {
		if (strcmp(*argv, "pipeid") == 0) {
			NEXT_ARG();
			if (get_u32(&pipeid, *argv, 10) < 0) {
				ret = -1;
				goto unregister;
			}
		} else if (strcmp(*argv, "actid") == 0) {
			NEXT_ARG();
			if (get_u32(&actid, *argv, 10) < 0) {
				ret = -1;
				goto unregister;
			}
		} else if (strcmp(*argv, "cmd") == 0) {
			ins_cnt = parse_commands(a, &argc, &argv);
			if (ins_cnt < 0) {
				ret = -1;
				goto unregister;
			}
		} else {
			if (parse_dyna(&argc, &argv, false, pname, full_actname, n) < 0) {
				ret = -1;
				goto unregister;
			}
		}
		argv++;
		argc--;
	}
	if (!STR_IS_EMPTY(full_actname))
		addattrstrz(n, MAX_MSG, P4TC_ACT_NAME, full_actname);

	if (add_commands(n, ins_cnt, P4TC_ACT_METACT_LIST) < 0) {
		ret = -1;
		goto unregister;
	}

	addattr_nest_end(n, tail);
	if (actid)
		addattr32(n, MAX_MSG, P4TC_PATH, actid);
	if (!actid && !cbname && !actname)
		*flags |= NLM_F_ROOT;
	addattr_nest_end(n, count);

	ret = pipeid;

unregister:
	unregister_kernel_metadata();

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

static int parse_hdrfield_data(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			       char *p4tcpath[], int cmd, unsigned int *flags)
{
	__u32 pipeid = 0, parser_id = 0, hdrfield_id = 0;
	struct p4tc_header_field_ty hdr_ty = {0};
	struct hdrfield fields[32] = {0};
	struct hdrfield *field = NULL;
	struct rtattr *count = NULL;
	char **argv = *argv_p;
	int argc = *argc_p;
	int num_fields = 0;
	/* Parser instance id + header field id */
	__u32 ids[2] = {0};
	char *pname, *parser_name, *hdrname, *fieldname;
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
		}

		argv++;
		argc--;
	}

	pname = p4tcpath[PATH_PNAME_IDX];
	parser_name = p4tcpath[PATH_PARSERNAME_IDX];
	hdrname = p4tcpath[PATH_HDRNAME_IDX];
	fieldname = p4tcpath[PATH_HDRFIELDNAME_IDX];
	if (pname && hdrname) {
		num_fields = p4tc_get_header_fields(fields, pname, hdrname,
						    &pipeid);
		if (num_fields < 0)
			return num_fields;
	}

	if (hdrname && fieldname) {
		field = p4tc_find_hdrfield(fields, fieldname, num_fields);
		if (!field) {
			fprintf(stderr,
				"Unable to find header field in introspection file\n");
			return -1;
		}

		hdr_ty.datatype = field->ty->containid;
		hdr_ty.startbit = field->startbit;
		hdr_ty.endbit = field->endbit;

		ids[1] = field->id;
	} else if (hdrfield_id) {
		ids[1] = hdrfield_id;
	} else if (cmd != RTM_NEWP4TEMPLATE) {
		*flags |= NLM_F_ROOT;
	}

	/* Always add count nest unless it's a dump */
	if (!((*flags & NLM_F_ROOT) && cmd == RTM_GETP4TEMPLATE))
		count = addattr_nest(n, MAX_MSG, 1);

	if (parser_id)
		ids[0] = parser_id;
	addattr_l(n, MAX_MSG, P4TC_PATH, ids, sizeof(ids));

	tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS);
	if (parser_name)
		addattrstrz(n, MAX_MSG, P4TC_HDRFIELD_PARSER_NAME,
			    parser_name);
	if (fieldname) {
		concat_cb_name(full_hdr_name, hdrname, fieldname,
			       HDRFIELDNAMSIZ);
		addattrstrz(n, MAX_MSG, P4TC_HDRFIELD_NAME, full_hdr_name);
		if (cmd == RTM_NEWP4TEMPLATE) {
			addattr_l(n, MAX_MSG, P4TC_HDRFIELD_DATA, &hdr_ty,
				  sizeof(hdr_ty));
		}
	}
	addattr_nest_end(n, tail);

	if (count)
		addattr_nest_end(n, count);

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

static int parse_table_instance_data(int *argc_p, char ***argv_p,
				     struct nlmsghdr *n, char *p4tcpath[],
				     int cmd, unsigned int *flags)
{
	char *cbname = NULL, *tbcname = NULL, *tiname = NULL;
	char full_tbcname[TCLASSNAMSIZ] = {0};
	__u32 pipeid = 0, tbc_id = 0, ti_id = 0;
	bool set_max_entries = false;
	struct rtattr *count = NULL;
	char **argv = *argv_p;
	__u32 maxentries = 0;
	int argc = *argc_p;
	int ret = 0;
	struct rtattr *tail;
	__u32 path[2];

	cbname = p4tcpath[PATH_CBNAME_IDX];
	tbcname = p4tcpath[PATH_TBCNAME_IDX];
	tiname = p4tcpath[PATH_TINAME_IDX];

	while (argc > 0) {
		if (cmd == RTM_NEWP4TEMPLATE) {
			if (strcmp(*argv, "maxentries") == 0) {
				NEXT_ARG();
				if (get_u32(&maxentries, *argv, 10) < 0)
					return -1;
				set_max_entries = true;
			} else if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "tbcid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbc_id, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "tinstid") == 0) {
				NEXT_ARG();
				if (get_u32(&ti_id, *argv, 10) < 0)
					return -1;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
		} else {
			if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "tbcid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbc_id, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "tinstid") == 0) {
				NEXT_ARG();
				if (get_u32(&ti_id, *argv, 10) < 0)
					return -1;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
		}
		argv++;
		argc--;
	}

	if (!tiname && !ti_id)
		*flags |= NLM_F_ROOT;

	/* Always add count nest unless it's a dump */
	if (!((*flags & NLM_F_ROOT) && cmd == RTM_GETP4TEMPLATE))
		count = addattr_nest(n, MAX_MSG, 1);

	path[0] = tbc_id;
	path[1] = ti_id;
	addattr_l(n, MAX_MSG, P4TC_PATH, path, sizeof(__u32) * 2);

	tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS);
	if (!tail)
		return -1;

	if (cbname && tbcname) {
		ret = concat_cb_name(full_tbcname, cbname, tbcname,
				     TCLASSNAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "table class name too long\n");
			return -1;
		}
	}

	if (!STR_IS_EMPTY(full_tbcname))
		addattrstrz(n, MAX_MSG, P4TC_TINST_CLASS, full_tbcname);
	if (tiname)
		addattrstrz(n, MAX_MSG, P4TC_TINST_NAME, tiname);
	if (set_max_entries)
		addattr32(n, MAX_MSG, P4TC_TINST_MAX_ENTRIES, maxentries);
	addattr_nest_end(n, tail);

	if (count)
		addattr_nest_end(n, count);

	*argc_p = argc;
	*argv_p = argv;

	return pipeid;
}

static int tc_parse_table_key(struct nlmsghdr *n, int current_key,
			      bool *is_default, int *argc_p, char ***argv_p)
{
	struct rtattr *tail;
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret = 0;

	argc -= 1;
	argv += 1;

	tail = addattr_nest(n, MAX_MSG, current_key + 1);
	while (argc > 0) {
		if (strcmp(*argv, "id") == 0) {
			__u32 id;

			NEXT_ARG();
			if (get_u32(&id, *argv, 10) < 0) {
				ret = -1;
				goto out;
			}
			addattr32(n, MAX_MSG, P4TC_KEY_ID, id);
		} else if (strcmp(*argv, "default") == 0) {
			*is_default = true;
		} else if (matches(*argv, "action") == 0) {
			if (parse_action(&argc, &argv, P4TC_KEY_ACT, n)) {
				fprintf(stderr, "Illegal action\n");
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "keys") == 0) {
			ret = 1;
			goto close_nested;
		} else if (strcmp(*argv, "postactions") == 0) {
			ret = 0;
			goto close_nested;
		} else if (strcmp(*argv, "preactions") == 0) {
			ret = 0;
			goto close_nested;
		} else {
			ret = -1;
			goto out;
		}
		argv++;
		argc--;
	}

close_nested:
	addattr_nest_end(n, tail);

out:
	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

static int parse_table_class_data(int *argc_p, char ***argv_p,
				  struct nlmsghdr *n, char *p4tcpath[],
				  int cmd, unsigned int *flags)
{
	struct p4tc_table_class_parm tclass = {0};
	char full_tbcname[TCLASSNAMSIZ] = {0};
	struct rtattr *count = NULL;
	struct rtattr *tail2 = NULL;
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	int current_key = 0;
	int argc = *argc_p;
	__u32 tbc_id = 0;
	__u32 pipeid = 0;
	int ret = 0;
	char *cbname, *tbcname;
	bool is_default;

	cbname = p4tcpath[PATH_CBNAME_IDX];
	tbcname = p4tcpath[PATH_TBCNAME_IDX];
	count = addattr_nest(n, MAX_MSG, 1);
	tail = addattr_nest(n, MAX_MSG, P4TC_PARAMS);
	while (argc > 0) {
		is_default = false;
		if (cmd == RTM_NEWP4TEMPLATE) {
			if (strcmp(*argv, "tbcid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbc_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else if (strcmp(*argv, "keysz") == 0) {
				NEXT_ARG();
				if (get_u32(&tclass.tbc_keysz, *argv, 10) < 0)
					return -1;
				tclass.tbc_flags |= P4TC_TCLASS_FLAGS_KEYSZ;
			} else if (strcmp(*argv, "tcount") == 0) {
				NEXT_ARG();
				if (get_u32(&tclass.tbc_count, *argv, 10) < 0)
					return -1;
				tclass.tbc_flags |= P4TC_TCLASS_FLAGS_COUNT;
			} else if (strcmp(*argv, "tentries") == 0) {
				NEXT_ARG();
				if (get_u32(&tclass.tbc_max_entries, *argv, 10) < 0)
					return -1;
				tclass.tbc_flags |= P4TC_TCLASS_FLAGS_MAX_ENTRIES;
			} else if (strcmp(*argv, "nummasks") == 0) {
				NEXT_ARG();
				if (get_u32(&tclass.tbc_max_masks, *argv, 10) < 0)
					return -1;
				tclass.tbc_flags |= P4TC_TCLASS_FLAGS_MAX_MASKS;
			} else if (strcmp(*argv, "keys") == 0) {
				if (!tail2) {
					tail2 = addattr_nest(n, MAX_MSG,
							     P4TC_TCLASS_KEYS);
				}
				ret = tc_parse_table_key(n, current_key,
							 &is_default, &argc,
							 &argv);

				if ((tclass.tbc_flags & P4TC_TCLASS_FLAGS_DEFAULT_KEY) &&
				    is_default) {
					fprintf(stderr,
						"Unable to set default key twice");
					return -1;
				}

				current_key++;

				if (is_default) {
					tclass.tbc_default_key = current_key;
					tclass.tbc_flags |= P4TC_TCLASS_FLAGS_DEFAULT_KEY;
				}

				if (ret < 0)
					goto out;
				/* More table keys to go*/
				else if (ret == 1)
					continue;
				else {
					addattr_nest_end(n, tail2);
					continue;
				}
			} else if (strcmp(*argv, "preactions") == 0) {
				argv++;
				argc--;
				if (parse_action(&argc, &argv,
						 P4TC_TCLASS_PREACTIONS, n)) {
					fprintf(stderr, "Illegal action\n");
					return -1;
				}
				continue;
			} else if (strcmp(*argv, "postactions") == 0) {
				argv++;
				argc--;
				if (parse_action(&argc, &argv,
						 P4TC_TCLASS_POSTACTIONS, n)) {
					fprintf(stderr, "Illegal action\n");
					return -1;
				}
				continue;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
		} else {
			if (strcmp(*argv, "tbcid") == 0) {
				NEXT_ARG();
				if (get_u32(&tbc_id, *argv, 10) < 0) {
					ret = -1;
					goto out;
				}
			} else if (strcmp(*argv, "pipeid") == 0) {
				NEXT_ARG();
				if (get_u32(&pipeid, *argv, 10) < 0)
					return -1;
			} else {
				fprintf(stderr, "Unknown arg %s\n", *argv);
				return -1;
			}
		}
		argv++;
		argc--;
	}

	if (cmd == RTM_NEWP4TEMPLATE)
		addattr_l(n, MAX_MSG, P4TC_TCLASS_INFO, &tclass,
			  sizeof(tclass));

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
		addattrstrz(n, MAX_MSG, P4TC_TCLASS_NAME, full_tbcname);

	addattr_nest_end(n, tail);

	if (!cbname && !tbcname && !tbc_id)
		*flags |= NLM_F_ROOT;

	if (tbc_id)
		addattr32(n, MAX_MSG, P4TC_PATH, tbc_id);

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
		if (cmd == RTM_NEWP4TEMPLATE) {
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

	count = addattr_nest(n, MAX_MSG, 1);
	if (!cbname && !mname && !mid)
		*flags |= NLM_F_ROOT;

	if (mid)
		addattr32(n, MAX_MSG, P4TC_PATH, mid);

	if (meta_flags & P4TC_FLAGS_META_SIZE || !STR_IS_EMPTY(full_mname)) {
		nest = addattr_nest(n, MAX_MSG, P4TC_PARAMS);

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
	__u16 numtclasses;

	if (cmd == RTM_NEWP4TEMPLATE) {
		count = addattr_nest(n, MAX_MSG, 1);
		nest = addattr_nest(n, MAX_MSG, P4TC_PARAMS);

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
			} else if (strcmp(*argv, "numtclasses") == 0) {
				NEXT_ARG();
				if (get_u16(&numtclasses, *argv, 10) < 0)
					return -1;

				addattr16(n, MAX_MSG, P4TC_PIPELINE_NUMTCLASSES,
					  numtclasses);
			} else if (strcmp(*argv, "preactions") == 0) {
				argv++;
				argc--;
				if (parse_action(&argc, &argv,
						 P4TC_PIPELINE_PREACTIONS, n)) {
					fprintf(stderr, "Illegal action\n");
					return -1;
				}
				continue;
			} else if (strcmp(*argv, "postactions") == 0) {
				argv++;
				argc--;
				if (parse_action(&argc, &argv,
						 P4TC_PIPELINE_POSTACTIONS, n)) {
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
		count = addattr_nest(n, MAX_MSG, 1);
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

	if (cmd == RTM_NEWP4TEMPLATE) {
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

	parse_path(*argv, p4tcpath);
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
	root = addattr_nest(&req.n, MAX_MSG, P4TC_ROOT);

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
	case P4TC_OBJ_TABLE_CLASS:
		pipeid = parse_table_class_data(&argc, &argv, &req.n, p4tcpath,
						cmd, &flags);
		if (pipeid < 0)
			return -1;
		req.t.pipeid = pipeid;

		break;
	case P4TC_OBJ_TABLE_INST:
		pipeid = parse_table_instance_data(&argc, &argv, &req.n,
						   p4tcpath, cmd, &flags);
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
			ret = p4tmpl_cmd(RTM_NEWP4TEMPLATE,
					 NLM_F_EXCL | NLM_F_CREATE, &argc,
					 &argv);
		} else if (matches(*argv, "update") == 0) {
			ret = p4tmpl_cmd(RTM_NEWP4TEMPLATE, NLM_F_REPLACE,
					 &argc, &argv);
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
