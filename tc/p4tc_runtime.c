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
#include "p4tc_common.h"
#include "p4_types.h"
#include "p4tc_filter.h"

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

int print_p4ctrl(struct nlmsghdr *n, void *arg)
{
	struct p4tcmsg *t = NLMSG_DATA(n);

	switch (t->obj) {
	case P4TC_OBJ_RUNTIME_TABLE:
		return print_table(n, arg);
	default:
		return 0;
	}
}

static int tc_table_cmd(int cmd, unsigned int flags, int *argc_p, char ***argv_p)
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
		register_known_unprefixed_names();
		ret = parse_table_entry(cmd, &argc, &argv, p4tcpath,
					&req.n, &flags);
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
			ret = tc_table_cmd(RTM_P4TC_CREATE,
					   NLM_F_EXCL | NLM_F_CREATE, &argc,
					   &argv);
		} else if (matches(*argv, "update") == 0) {
			ret = tc_table_cmd(RTM_P4TC_UPDATE, 0, &argc, &argv);
		} else if (matches(*argv, "get") == 0) {
			ret = tc_table_cmd(RTM_P4TC_GET, 0, &argc, &argv);
		} else if (matches(*argv, "delete") == 0) {
			ret = tc_table_cmd(RTM_P4TC_DEL, 0, &argc, &argv);
		} else {
			help_p4ctrl();
			return -1;
		}

		if (ret < 0)
			return -1;
	}

	return 0;
}
