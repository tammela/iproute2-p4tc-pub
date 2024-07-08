/*
 * p4tc_runtime.c		P4 TC Runtime Management
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
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
#include "p4tc_common.h"
#include "p4_types.h"
#include "p4tc_filter.h"
#include "p4tc_filter_parser.h"

static void help_p4ctrl(void)
{
	fprintf(stderr,
		"Usage: tc p4ctrl [COMMAND] PNAME/OBJTYPE/OBJPATH OBJATTRS\n"
		"where:\n"
		"\tCOMMAND := <create | update | get | delete | help>\n"
		"\tPNAME is the pipeline name\n"
		"\tOBJTYPE := <table | extern>\n"
		"\tOBJPATH := path to the object, example mycontrolblock/mytable\n"
		"\tOBJATTRS are the object specific attributes, example entry keys\n");
}

struct nl_req {
	struct nlmsghdr n;
	struct p4tcmsg t;
	char buf[MAX_MSG];
};

static int tc_filter_common(struct p4tc_filter_ctx *ctx, struct nl_req *req,
			    struct typedexpr **typed_expr, int *argc_p,
			    char ***argv_p, bool *has_extra_args)
{
	struct parsedexpr *parsed_expr = NULL;
	char **argv = *argv_p;
	int argc = *argc_p;

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct p4tcmsg));
	req->n.nlmsg_flags = NLM_F_REQUEST;
	req->n.nlmsg_type = RTM_P4TC_CREATE;

	NEXT_ARG_FWD();

	*has_extra_args = !!argc;
	if (*has_extra_args && strcmp(*argv, "filter")) {
		fprintf(stderr, "Invalid argument %s\n", *argv);
		return -1;
	}

	req->t.obj = ctx->obj_id;

	if (*has_extra_args) {
		NEXT_ARG();

		parsed_expr = parse_expr_args(&argc,
					      (const char * const **)&argv,
					      NULL);
		if (parsed_expr->t == ET_ERR) {
			fprintf(stderr, "Failed to parse expr: %s\n",
				parsed_expr->errmsg);
			return -1;
		}

		*typed_expr = type_expr(ctx, parsed_expr);
		free_parsedexpr(parsed_expr);
		if ((*typed_expr)->t == ET_ERR) {
			fprintf(stderr, "Failed to type expr: %s\n",
				(*typed_expr)->errmsg_fmt);
			return -1;
		}
		dump_typed_expr(*typed_expr, 0);
	}

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int tc_filter_add_attrs(struct rtnl_handle *rth, struct nl_req *req,
			       struct typedexpr *typed_expr, const __u32 attr)
{
	struct rtattr *tail3 = NULL, *tail4 = NULL;


	tail3 = addattr_nest(&req->n, MAX_MSG, attr | NLA_F_NESTED);
	tail4 = addattr_nest(&req->n, MAX_MSG, P4TC_FILTER_OP | NLA_F_NESTED);
	add_typed_expr(&req->n, typed_expr);

	if (tail4)
		addattr_nest_end(&req->n, tail4);
	if (tail3)
		addattr_nest_end(&req->n, tail3);

	return 0;
}

static int tc_table_filter(struct rtnl_handle *rth, int *argc_p, char ***argv_p,
			   char **p4tcpath)
{
	const char *pname = p4tcpath[PATH_RUNTIME_PNAME_IDX];
	const char *tblname = p4tcpath[PATH_TBLNAME_IDX];
	const char *cbname = p4tcpath[PATH_CBNAME_IDX];
	char full_tblname[P4TC_TABLE_NAMSIZ] = {0};
	struct typedexpr *typed_expr = NULL;
	struct p4tc_filter_ctx ctx = {};
	struct p4tc_json_pipeline *p;
	struct rtattr *tail, *tail2;
	struct p4tc_json_table *t;
	char **argv = *argv_p;
	int argc = *argc_p;
	struct nl_req req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct p4tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_P4TC_CREATE,
	};
	bool has_extra_args;
	int ret;

	p = p4tc_json_import(pname);
	if (!p) {
		fprintf(stderr, "Unable to find pipeline %s\n",
			pname);
		return -1;
	}
	ctx.p = p;

	if (concat_cb_name(full_tblname, cbname, tblname, P4TC_TABLE_NAMSIZ) < 0) {
		fprintf(stderr, "Table name to long %s/%s\n", cbname, tblname);
		ret = -1;
		goto clear_ctx;
	}

	t = p4tc_json_find_table(p, full_tblname);
	if (!t) {
		fprintf(stderr, "Unable to find table %s\n", tblname);
		ret = -1;
		goto clear_ctx;
	}
	ctx.t = t;
	ctx.obj_id = P4TC_OBJ_RUNTIME_TABLE;

	ret = tc_filter_common(&ctx, &req, &typed_expr, &argc, &argv,
			       &has_extra_args);
	if (ret < 0)
		return ret;

	if (pname)
		addattrstrz(&req.n, MAX_MSG, P4TC_ROOT_PNAME, pname);

	tail = addattr_nest(&req.n, MAX_MSG,
			    P4TC_ROOT_SUBSCRIBE | NLA_F_NESTED);

	addattr32(&req.n, MAX_MSG, P4TC_PATH, 0);

	tail2 = addattr_nest(&req.n, MAX_MSG,
			     P4TC_PARAMS | NLA_F_NESTED);

	if (!STR_IS_EMPTY(full_tblname))
		addattrstrz(&req.n, MAX_MSG, P4TC_ENTRY_TBLNAME, full_tblname);

	if (has_extra_args) {
		ret = tc_filter_add_attrs(rth, &req, typed_expr,
					  P4TC_ENTRY_FILTER);

		if (ret < 0)
			goto free_typed_expr;
	}

	addattr_nest_end(&req.n, tail2);
	addattr_nest_end(&req.n, tail);

	ret = rtnl_talk(rth, &req.n, NULL);
	if (ret < 0)
		goto free_typed_expr;

	*argc_p = argc;
	*argv_p = argv;

free_typed_expr:
	free_typedexpr(typed_expr);
clear_ctx:
	p4tc_filter_ctx_free(&ctx);
	return ret;
}

#define P4TC_CMD_NAME_IDX 1

int tc_p4ctrl_filter(struct rtnl_handle *rth, int *argc_p, char ***argv_p)
{
	char *p4tcpath[MAX_PATH_COMPONENTS] = {NULL};
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret;

	NEXT_ARG();
	parse_path(*argv, p4tcpath, "/");
	if (!p4tcpath[PATH_TABLE_OBJ_IDX]) {
		fprintf(stderr, "Must specify obj type\n");
		return -1;
	}

	if (strcmp(p4tcpath[PATH_TABLE_OBJ_IDX], "table") == 0) {
		ret = tc_table_filter(rth, &argc, &argv, p4tcpath);
	} else {
		fprintf(stderr, "Unknown filter object %s\n", *argv);
		return -1;
	}

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

int print_p4ctrl(struct nlmsghdr *n, void *arg)
{
	struct p4tcmsg *t = NLMSG_DATA(n);

	switch (t->obj) {
	case P4TC_OBJ_RUNTIME_TABLE:
		return print_table(n, arg);
	case P4TC_OBJ_RUNTIME_EXTERN:
		return print_extern(n, arg);
	default:
		return 0;
	}
}

static int tc_runtime_cmd(int cmd, unsigned int flags, int *argc_p, char ***argv_p)
{
	char *p4tcpath[MAX_PATH_COMPONENTS] = {NULL};
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *root;
	int ret = -1;

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

	parse_path(*argv, p4tcpath, "/");
	if (!p4tcpath[PATH_TABLE_OBJ_IDX])
		return -1;

	req.t.obj = get_obj_runtime_type(p4tcpath[PATH_TABLE_OBJ_IDX]);
	if (req.t.obj < 0) {
		fprintf(stderr, "Unknown runtime object type %s\n",
			p4tcpath[PATH_TABLE_OBJ_IDX]);
		return -1;
	}
	argc -= 1;
	argv += 1;

	switch (req.t.obj) {
	case P4TC_OBJ_RUNTIME_TABLE:
		if (argc > 0 && strcmp(*argv, "help") == 0)
			return parse_table_entry_help(cmd, p4tcpath);
		break;
	case P4TC_OBJ_RUNTIME_EXTERN:
		if (argc > 0 && strcmp(*argv, "help") == 0)
			return parse_extern_help(cmd, p4tcpath);
		break;
	default:
		fprintf(stderr, "Unknown runtime object");
		return -1;
	}

	if (p4tcpath[PATH_TABLE_PNAME_IDX])
		addattrstrz(&req.n, MAX_MSG, P4TC_ROOT_PNAME,
			p4tcpath[PATH_TABLE_PNAME_IDX]);

	root = addattr_nest(&req.n, MAX_MSG, P4TC_ROOT | NLA_F_NESTED);

	switch (req.t.obj) {
	case P4TC_OBJ_RUNTIME_TABLE: {
		ret = parse_table_entry(cmd, &argc, &argv, p4tcpath,
					&req.n, &flags);
		if (ret < 0)
			return ret;
		break;
	}
	case P4TC_OBJ_RUNTIME_EXTERN: {
		ret = parse_p4tc_extern(&req.n, cmd, &flags, &argc, &argv,
					(const char **)p4tcpath);
		if (ret < 0)
			return ret;
		break;
	}
	default:
		break;
	}
	req.t.pipeid = ret;

	req.n.nlmsg_flags = NLM_F_REQUEST | flags,
	addattr_nest_end(&req.n, root);

	if (cmd == RTM_P4TC_GET) {
		if (flags & NLM_F_ROOT) {
			int msg_size;

			msg_size = NLMSG_ALIGN(req.n.nlmsg_len) -
				NLMSG_ALIGN(sizeof(struct nlmsghdr));
			if (rtnl_dump_request(&rth, RTM_P4TC_GET,
					      (void *)&req.t, msg_size) < 0) {
				perror("Cannot send dump request");
				return -1;
			}

			new_json_obj(json);
			if (rtnl_dump_filter(&rth, print_p4ctrl, stdout) < 0) {
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
			print_p4ctrl(ans, stdout);
			delete_json_obj();
			free(ans);
		}
	} else {
		if (echo_request)
			ret = rtnl_echo_talk(&rth, &req.n, json,
					     print_p4ctrl);
		else
			ret = rtnl_talk(&rth, &req.n, NULL);

		if (ret < 0) {
			fprintf(stderr, "We have an error talking to the kernel\n");
			return -1;
		}
	}

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

int do_p4_runtime(int argc, char **argv)
{
	int ret = 0;

	while (argc > 0) {
		if (matches(*argv, "create") == 0) {
			ret = tc_runtime_cmd(RTM_P4TC_CREATE,
					     NLM_F_EXCL | NLM_F_CREATE, &argc,
					     &argv);
		} else if (matches(*argv, "update") == 0) {
			ret = tc_runtime_cmd(RTM_P4TC_UPDATE, 0, &argc, &argv);
		} else if (matches(*argv, "get") == 0) {
			ret = tc_runtime_cmd(RTM_P4TC_GET, 0, &argc, &argv);
		} else if (matches(*argv, "delete") == 0) {
			ret = tc_runtime_cmd(RTM_P4TC_DEL, 0, &argc, &argv);
		} else {
			help_p4ctrl();
			return -1;
		}

		if (ret < 0)
			return -1;
	}

	return 0;
}
