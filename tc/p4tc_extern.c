/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * p4tc_extern.c		P4TC Externs management
 *
 *              This program is free software; you can distribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2022-24, Mojatatu Networks
 * Copyright (c) 2022-24, Intel Corporation.
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
#include <errno.h>
#include <linux/p4tc_ext.h>

#include "utils.h"
#include "tc_common.h"
#include "tc_util.h"
#include "p4tc_common.h"
#include "p4tc_filter.h"

static int parse_p4tc_extern_params(int *argc_p, char ***argv_p,
				    struct p4tc_json_extern_insts_list *inst,
				    struct nlmsghdr *n)
{
	struct rtattr *tail = NULL, *tail_key = NULL;
	char **argv = *argv_p;
	int parms_count = 1;
	int argc = *argc_p;

	while (argc > 0) {
		if (strcmp(*argv, "param") == 0 ||
		    strcmp(*argv, "tc_data_scalar") == 0) {
			if (!tail)
				tail = addattr_nest(n, MAX_MSG,
						    P4TC_EXT_PARAMS | NLA_F_NESTED);

			if (p4tc_extern_parse_inst_param(&argc, &argv, true,
							 &parms_count, inst, n) < 0)
				return -1;

			if (argc && (strcmp(*argv, "param") == 0 ||
				     strcmp(*argv, "tc_key") == 0 ||
				     strcmp(*argv, "tc_data_scalar") == 0))
				continue;
		} else if (strcmp(*argv, "tc_key") == 0)  {
			if (tail) {
				fprintf(stderr,
					"Must specify tc_key before other parameters\n");
				return -1;
			}

			if (tail_key) {
				fprintf(stderr, "Mustn't specify 2 tc_keys\n");
				return -1;
			}
			tail_key = addattr_nest(n, MAX_MSG,
						P4TC_EXT_KEY | NLA_F_NESTED);

			if (p4tc_extern_parse_inst_param(&argc, &argv, true,
							 &parms_count, inst, n) < 0)
				return -1;
			addattr_nest_end(n, tail_key);
		} else if (strcmp(*argv, "action") == 0) {
			goto tail_end;
		} else {
			break;
		}
		argv++;
		argc--;
	}

tail_end:
	if (tail)
		addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static void print_ext_inst_param_help(struct p4tc_json_extern_insts_data *param)
{

	fprintf(stderr, "\t    param name %s\n", param->name);
	fprintf(stderr, "\t    param id %u\n", param->id);
	fprintf(stderr, "\t    param type %s\n", param->type);

	if (strcmp(param->attr, "tc_key") == 0)
		fprintf(stderr, "\t    param is key\n");

	print_nl();
}

static void print_ext_inst_params_help(struct p4tc_json_extern_insts_list *inst)
{
	struct p4tc_json_extern_insts_data *param;

	param = p4tc_json_ext_insts_data_start_iter(inst);
	if (!param)
		return;

	fprintf(stderr, "\t  Params for %s:\n", inst->name);
	while (param) {
		print_ext_inst_param_help(param);
		param = p4tc_json_ext_insts_data_iter_next(param);
	}
}

static void print_ext_inst_help(struct p4tc_json_extern_insts_list *inst)
{
	fprintf(stderr, "\t  extern instance name %s\n", inst->name);
	fprintf(stderr, "\t  extern instance id %u\n", inst->id);

	print_ext_inst_params_help(inst);
	print_nl();
}

static void print_ext_insts_help(struct p4tc_json_externs_list *e)
{
	struct p4tc_json_extern_insts_list *insts_list;

	print_nl();
	fprintf(stderr, "Instances for extern %s:\n", e->name);

	insts_list = p4tc_json_ext_inst_iter_start(e);
	while (insts_list) {
		print_ext_inst_help(insts_list);
		insts_list = p4tc_json_ext_inst_iter_next(insts_list);
	}
}

static void print_extern_help(struct p4tc_json_externs_list *e)
{
	fprintf(stderr, "\t  extern name %s\n", e->name);
	fprintf(stderr, "\t  extern id %u\n", e->id);
	print_nl();
}

static void print_externs_help(struct p4tc_json_pipeline *p)
{
	struct p4tc_json_externs_list *exts_list;

	print_nl();
	fprintf(stderr, "Externs for pipeline %s:\n", p->name);

	exts_list = p4tc_json_extern_iter_start(p);
	while (exts_list) {
		print_extern_help(exts_list);
		exts_list = p4tc_json_extern_iter_next(exts_list);
	}
}

int parse_extern_help(int cmd, char **p4tcpath)
{
	const char *inst = p4tcpath[PATH_RUNTIME_EXTINSTNAME_IDX];
	const char *k = p4tcpath[PATH_RUNTIME_EXTNAME_IDX];
	const char *pname = p4tcpath[PATH_TABLE_PNAME_IDX];
	struct p4tc_json_extern_insts_list *inst_list;
	struct p4tc_json_externs_list *ext_list;
	struct p4tc_json_pipeline *p;

	p = p4tc_json_import(pname);
	if (!p) {
		fprintf(stderr, "Unable to find pipeline %s\n",
			pname);
		return -1;
	}

	if (!k) {
		print_externs_help(p);
		return 0;
	}

	ext_list = p4tc_json_find_extern(p, k);
	if (!ext_list) {
		fprintf(stderr,
			"Unable to find extern %s in instropection file\n", k);
		return 0;
	}

	if (!inst) {
		print_ext_insts_help(ext_list);
		return 0;
	}

	inst_list = p4tc_json_find_extern_inst(p, k, inst);
	if (!inst_list) {
		fprintf(stderr, "Unable to find extern inst %s\n", k);
		return -1;
	}

	print_ext_inst_help(inst_list);
	return 0;
}

int parse_p4tc_extern_common(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			     const char *pname, const char *inst, const char *k,
			     bool add_prio_nest)
{
	struct p4tc_json_extern_insts_list *inst_list;
	struct p4tc_json_pipeline *p;
	char **argv = *argv_p;
	struct rtattr *tail;
	int argc = *argc_p;
	int ret = -1;
	int prio = 0;

	if (argc <= 0)
		return -1;

	p = p4tc_json_import(pname);
	if (!p) {
		fprintf(stderr, "Unable to find pipeline %s\n",
			pname);
		return -1;
	}
	inst_list = p4tc_json_find_extern_inst(p, k, inst);
	if (!inst_list) {
		fprintf(stderr, "Unable to find extern inst %s\n", inst);
		goto free_pipe;
	}

	while (argc > 0) {
		if (add_prio_nest)
			tail = addattr_nest(n, MAX_MSG, ++prio | NLA_F_NESTED);
		addattrstrz(n, MAX_MSG, P4TC_EXT_KIND, k);
		addattrstrz(n, MAX_MSG, P4TC_EXT_INST_NAME, inst);

		ret = parse_p4tc_extern_params(&argc, &argv, inst_list, n);
		if (ret < 0) {
			fprintf(stderr, "bad extern parsing\n");
			goto bad_val;
		}

		if (add_prio_nest)
			addattr_nest_end(n, tail);

		if (argc && strcmp(*argv, "action") == 0)
			break;

		argc--;
		argv++;
	}

	*argc_p = argc;
	*argv_p = argv;

	ret = 0;
	goto free_pipe;

bad_val:
	fprintf(stderr, "%s: bad value (%d:%s)!\n", __func__, argc,
		*argv);
free_pipe:
	p4tc_json_free_pipeline(p);
	return ret;
}

static int __parse_p4tc_extern(int *argc_p, char ***argv_p, struct nlmsghdr *n,
			       const char **p4tcpath)
{
	const char *inst = p4tcpath[PATH_RUNTIME_EXTINSTNAME_IDX];
	const char *k = p4tcpath[PATH_RUNTIME_EXTNAME_IDX];
	const char *pname = p4tcpath[PATH_TABLE_PNAME_IDX];
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret;

	if (argc <= 0)
		return -1;

	ret = parse_p4tc_extern_common(&argc, &argv, n, pname, inst, k, true);

	*argc_p = argc;
	*argv_p = argv;

	return ret;

}

int p4tc_print_one_extern(FILE *f, struct p4tc_json_pipeline *pipe,
			  struct rtattr *arg, bool bind)
{

	struct p4tc_json_extern_insts_list *insts_list = NULL;
	struct rtattr *tb[P4TC_EXT_MAX + 1];
	char *kind, *inst;
	__u32 *key;

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, P4TC_EXT_MAX, arg);

	if (tb[P4TC_EXT_KIND] == NULL) {
		fprintf(stderr, "NULL Extern!\n");
		return -1;
	}

	kind = RTA_DATA(tb[P4TC_EXT_KIND]);
	print_string(PRINT_ANY, "kind", "\t  Extern kind %s\n", kind);

	if (tb[P4TC_EXT_INST_NAME] == NULL) {
		fprintf(stderr, "NULL Extern Instance!\n");
		return -1;
	}

	inst = RTA_DATA(tb[P4TC_EXT_INST_NAME]);
	print_string(PRINT_ANY, "instance", "\t  Extern instance %s\n", inst);

	if (tb[P4TC_EXT_KEY] == NULL) {
		fprintf(stderr, "NULL Extern Key!\n");
		return -1;
	}
	key = RTA_DATA(tb[P4TC_EXT_KEY]);
	print_uint(PRINT_ANY, "key", "\t  Extern key %u\n", *key);

	if (pipe) {
		insts_list = p4tc_json_find_extern_inst(pipe, kind, inst);
		if (!insts_list)
			return -1;
	}

	if (tb[P4TC_EXT_PARAMS]) {
		print_string(PRINT_FP, NULL, "\t  Params:\n", NULL);
		print_nl();
		open_json_array(PRINT_JSON, "params");

		p4tc_extern_inst_print_params(tb[P4TC_EXT_PARAMS], insts_list,
					      f);
		close_json_array(PRINT_JSON, NULL);
	}

	return 0;
}

static int
p4tc_dump_extern(FILE *f, struct p4tc_json_pipeline *pipe,
		 const struct rtattr *arg, unsigned short tot_acts,
		 bool bind)
{
	int i;

	if (arg == NULL)
		return 0;

	if (!tot_acts)
		tot_acts = P4TC_MSGBATCH_SIZE;

	struct rtattr *tb[tot_acts + 1];

	parse_rtattr_nested(tb, tot_acts, arg);

	open_json_array(PRINT_JSON, "externs");
	for (i = 0; i <= tot_acts; i++) {
		if (tb[i]) {
			open_json_object(NULL);
			print_nl();
			print_uint(PRINT_ANY, "order",
				   "\textern order %u:\n", i);
			if (p4tc_print_one_extern(f, pipe, tb[i], bind) < 0)
				fprintf(stderr, "Error printing extern\n");
			close_json_object();
		}

	}
	close_json_array(PRINT_JSON, NULL);

	return 0;
}

int print_extern(struct nlmsghdr *n, void *arg)
{
	struct p4tc_json_pipeline *pipe = NULL;
	struct rtattr *tb[P4TC_ROOT_MAX+1];
	struct p4tcmsg *t = NLMSG_DATA(n);
	FILE *fp = (FILE *)arg;
	int len = n->nlmsg_len;
	__u32 *tot_exts = NULL;

	len -= NLMSG_LENGTH(sizeof(*t));

	if (len < 0) {
		fprintf(stderr, "Wrong len %d\n", len);
		return -1;
	}

	parse_rtattr_flags(tb, P4TC_ROOT_MAX, P4TC_RTA(t), len, NLA_F_NESTED);

	if (tb[P4TC_ROOT_COUNT])
		tot_exts = RTA_DATA(tb[P4TC_ROOT_COUNT]);

	open_json_object(NULL);
	print_uint(PRINT_ANY, "total exts", "total exts %u",
		   tot_exts ? *tot_exts : 0);
	print_nl();
	close_json_object();
	if (tb[P4TC_ROOT] == NULL) {
		if (n->nlmsg_type != RTM_P4TC_GET)
			fprintf(stderr, "%s: NULL kind\n", __func__);
		return -1;
	}

	if (n->nlmsg_type == RTM_P4TC_CREATE ||
	    n->nlmsg_type == RTM_P4TC_UPDATE) {
		if ((n->nlmsg_flags & NLM_F_CREATE) &&
		    !(n->nlmsg_flags & NLM_F_REPLACE)) {
			fprintf(fp, "Added extern ");
		} else if (n->nlmsg_flags & NLM_F_REPLACE) {
			fprintf(fp, "Replaced extern ");
		}
	}

	open_json_object(NULL);
	if (tb[P4TC_ROOT_PNAME]) {
		char *pname = RTA_DATA(tb[P4TC_ROOT_PNAME]);

		pipe = p4tc_json_import(pname);
		if (!pipe) {
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

	p4tc_dump_extern(fp, pipe, tb[P4TC_ROOT], tot_exts ? *tot_exts:0,
			 false);

	close_json_object();

	if (pipe)
		p4tc_json_free_pipeline(pipe);

	return 0;
}

static int parse_ext_filter(int *argc_p, char ***argv_p,
			    struct p4tc_filter_ctx *ctx, struct nlmsghdr *n)
{
	struct parsedexpr *parsed_expr;
	struct typedexpr *typed_expr;
	struct rtattr *tail, *tail2;
	char **argv = *argv_p;
	int argc = *argc_p;

	tail = addattr_nest(n, MAX_MSG, P4TC_EXT_FILTER | NLA_F_NESTED);
	tail2 = addattr_nest(n, MAX_MSG, P4TC_FILTER_OP | NLA_F_NESTED);

	parsed_expr = parse_expr_args(&argc, (const char * const **)&argv,
				      NULL);
	if (parsed_expr->t == ET_ERR) {
		fprintf(stderr, "Failed to parse expr: %s\n",
			parsed_expr->errmsg);
		return -1;
	}

	typed_expr = type_expr(ctx, parsed_expr);
	if (typed_expr->t == ET_ERR) {
		fprintf(stderr, "Failed to type expr: %s\n",
			typed_expr->errmsg_fmt);
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

static int p4tc_ext_gd(struct nlmsghdr *n, int cmd, unsigned int *flags,
		       int *argc_p, char ***argv_p, const char **p4tcpath)
{
	const char *inst = p4tcpath[PATH_RUNTIME_EXTINSTNAME_IDX];
	const char *k = p4tcpath[PATH_RUNTIME_EXTNAME_IDX];
	const char *pname = p4tcpath[PATH_TABLE_PNAME_IDX];
	struct p4tc_json_extern_insts_list *inst_list;
	struct p4tc_json_pipeline *p;
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	struct rtattr *tail2;
	int parms_count = 1;
	int argc = *argc_p;
	int prio = 0;
	int ret = -1;

	tail2 = addattr_nest(n, MAX_MSG, ++prio | NLA_F_NESTED);
	if (!k) {
		fprintf(stderr, "Must specify extern kind name\n");
		return -1;
	}
	addattrstrz(n, MAX_MSG, P4TC_EXT_KIND, k);
	if (!inst) {
		fprintf(stderr, "Must specify extern instance name\n");
		return -1;
	}
	addattrstrz(n, MAX_MSG, P4TC_EXT_INST_NAME, inst);

	p = p4tc_json_import(pname);
	if (!p) {
		fprintf(stderr, "Unable to find pipeline %s\n",
			pname);
		return -1;
	}

	inst_list = p4tc_json_find_extern_inst(p, k, inst);
	if (!inst_list) {
		fprintf(stderr, "Unable to find extern inst %s\n",
			pname);
		goto free_pipe;
	}

	if (argc) {
		if (strcmp(*argv, "tc_key") == 0) {
			if (!tail)
				tail = addattr_nest(n, MAX_MSG,
						    P4TC_EXT_KEY | NLA_F_NESTED);

			if (p4tc_extern_parse_inst_param(&argc, &argv, true,
							 &parms_count, inst_list, n) < 0)
				goto free_pipe;
		} else if (!tail && strcmp(*argv, "filter") == 0) {
			struct p4tc_filter_ctx ctx = {
				.p = p,
				.inst = inst_list,
				.obj_id = P4TC_OBJ_RUNTIME_EXTERN,
			};

			NEXT_ARG();

			if (parse_ext_filter(&argc, &argv, &ctx, n) < 0)
				goto free_pipe;
		} else {
			fprintf(stderr, "Unknown arg %s\n", *argv);
			goto free_pipe;
		}
		argv++;
		argc--;
	}

	if (tail)
		addattr_nest_end(n, tail);
	else
		*flags |= NLM_F_ROOT;

	addattr_nest_end(n, tail2);

	*argc_p = argc;
	*argv_p = argv;
	ret = 0;

free_pipe:
	if (p)
		p4tc_json_free_pipeline(p);
	return ret;
}

int parse_p4tc_extern(struct nlmsghdr *n, int cmd, unsigned int *flags,
		      int *argc_p, char ***argv_p, const char **p4tcpath)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret = 0;

	switch (cmd) {
	case RTM_P4TC_CREATE:
	case RTM_P4TC_UPDATE:
		if (__parse_p4tc_extern(&argc, &argv, n, p4tcpath)) {
			fprintf(stderr, "Illegal \"extern\"\n");
			return -1;
		}
		break;
	case RTM_P4TC_GET:
	case RTM_P4TC_DEL:
		ret = p4tc_ext_gd(n, cmd, flags, &argc, &argv, p4tcpath);
	}

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}
