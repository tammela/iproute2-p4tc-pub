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
#include "p4_types.h"

#include "p4tc_common.h"

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
	print_nl();

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
