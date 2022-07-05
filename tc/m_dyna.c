/*
 * m_dyna.c		Dynamic actions module
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <asm-generic/errno-base.h>
#include <errno.h>


#include "utils.h"
#include "rt_names.h"
#include "tc_util.h"
#include "tc_common.h"
#include "p4tc_common.h"
#include "p4_types.h"

static void explain(void)
{
	fprintf(stderr,
		"Usage:... actname <state STATE> [PARAM] <index INDEX> <CONTROL>\n"
		"\tPARAM := [STRING] <type TYPE> <id U32NUM> <VALUE>\n"
		"\tSTRING being an arbitrary string\n"
		"\tSTATE := <active | inactive>\n"
		"\tTYPE maybe any valid type, such u8, u16, u32 or ipv4\n"
		"\tU32NUM being an arbitrary u32\n"
		"\tVALUE being a value for the parameter\n"
		"\tINDEX := optional index value used\n"
		"\tCONTROL := reclassify|pipe|drop|continue|ok\n");
}

static void usage(void)
{
	explain();
	exit(-1);
}

struct param {
	char name[ACTPARAMNAMSIZ];
	__u32 id;
	__u32 type;
	__u32 bitsz;
};

static int dyna_add_param(struct param *param, const char *value, bool in_act,
			  struct nlmsghdr *n)
{
	int ret = 0;

	addattrstrz(n, MAX_MSG, P4TC_ACT_PARAMS_NAME, param->name);
	if (param->id)
		addattr32(n, MAX_MSG, P4TC_ACT_PARAMS_ID, param->id);
	if (param->type)
		addattr32(n, MAX_MSG, P4TC_ACT_PARAMS_TYPE, param->type);

	if (in_act) {
		struct p4_type_value val;
		struct rtattr *nest_val;
		struct p4_type_s *t;
		void *new_value;
		void *new_mask;
		__u32 sz;

		t = get_p4type_byid(param->type);
		if (!t) {
			fprintf(stderr, "Unknown param type %d\n", param->type);
			return -1;
		}
		sz = t->bitsz >> 3;
		new_value = calloc(1, sz);
		if (!new_value)
			return -1;
		new_mask = calloc(1, sz);
		if (!new_mask) {
			ret = -1;
			goto free_value;
		}

		val.value = new_value;
		val.mask = new_mask;
		val.bitsz = param->bitsz;
		if (t->parse_p4t &&
		    t->parse_p4t(&val, value, 0) < 0) {
			ret = -1;
			goto free_mask;
		}

		nest_val = addattr_nest(n, MAX_MSG,
					P4TC_ACT_PARAMS_VALUE | NLA_F_NESTED);
		addattr_l(n, MAX_MSG, P4TC_ACT_PARAMS_VALUE_RAW, new_value, sz);
		addattr_nest_end(n, nest_val);

		addattr_l(n, MAX_MSG, P4TC_ACT_PARAMS_MASK, new_mask, sz);

free_mask:
		free(new_mask);
free_value:
		free(new_value);
	}

	return ret;
}

static int dyna_param_copy_name(char *dst_pname, char *src_pname)
{
	if (strnlen(src_pname, ACTPARAMNAMSIZ) == ACTPARAMNAMSIZ)
		return -1;

	strcpy(dst_pname, src_pname);

	return 0;
}

static int dyna_parse_param(int *argc_p, char ***argv_p, bool in_act,
			    int *parms_count, struct actions_list *act,
			    struct nlmsghdr *n)
{
	struct action_data *param_info = NULL;
	struct param param = {0};
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail2;

	NEXT_ARG();
	tail2 = addattr_nest(n, MAX_MSG, *parms_count | NLA_F_NESTED);
	if (dyna_param_copy_name(param.name, *argv) < 0) {
		fprintf(stderr, "Param name too big");
		return -E2BIG;
	}

	if (act)
		param_info = p4tc_find_act_data(act, param.name);

	/* After we get the param name, we can look for it in the P4 JSON file.
	 * If the param is found, we can instrospect its type and ID.
	 */
	NEXT_ARG();

	if (param_info) {
		struct p4_type_s *t;

		t = get_p4type_byarg(param_info->type, &param.bitsz);
		if (!t) {
			fprintf(stderr, "Invalid type %s\n", param_info->type);
			return -1;
		}
		param.type = t->containid;

		param.id = param_info->id;
	}

	/* If user stil wants to specify type and id, let them overwrite it */
	while (argc > 0) {
		if (strcmp(*argv, "type") == 0) {
			struct p4_type_s *t;

			NEXT_ARG();
			t = get_p4type_byarg(*argv, &param.bitsz);
			if (!t) {
				fprintf(stderr, "Invalid type %s\n", *argv);
				return -1;
			}
			param.type = t->containid;
		} else if (strcmp(*argv, "id") == 0) {
			__u32 id;

			NEXT_ARG();
			if (get_u32(&id, *argv, 10)) {
				fprintf(stderr, "Invalid id %s\n",
					*argv);
				return -1;
			}
			param.id = id;
		} else {
			break;
		}
		argv++;
		argc--;
	}

	if (dyna_add_param(&param, *argv, in_act, n) < 0)
		return -1;

	if (!in_act)
		PREV_ARG();

	addattr_nest_end(n, tail2);
	(*parms_count)++;

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

#define DYNACT_PATH_PNAME_IDX 0
#define DYNACT_PATH_CBNAME_IDX 1
#define DYNACT_PATH_PIPEACTNAME_IDX 1
#define DYNACT_PATH_CBACTNAME_IDX 2

/* We assume 2 possible paths:
 * - pname/cbname/actname - For control block actions
 * - pname/actname - For pipeline actions
 */
static struct actions_list *introspect_action_byname(const char **p4tcpath)
{
	const char *pname, *actname;
	struct p4_tc_pipeline *pipe;
	struct actions_list *act;

	pname = p4tcpath[DYNACT_PATH_PNAME_IDX];
	pipe = p4_tc_import_json(pname);
	if (!pipe) {
		fprintf(stderr, "Unable to find pipeline %s\n",
			pname);
		return NULL;
	}

	if (p4tcpath[DYNACT_PATH_CBACTNAME_IDX]) {
		char act_and_cbname[ACTNAMSIZ] = {};
		const char *cbname;

		cbname = p4tcpath[DYNACT_PATH_CBNAME_IDX];
		actname = p4tcpath[DYNACT_PATH_CBACTNAME_IDX];

		snprintf(act_and_cbname, ACTNAMSIZ, "%s/%s", cbname, actname);

		act = p4tc_find_act(pipe, act_and_cbname);
		if (!act) {
			fprintf(stderr,"Unable to find action %s\n",
				act_and_cbname);
			return NULL;
		}
	} else if (p4tcpath[DYNACT_PATH_PIPEACTNAME_IDX]) {
		actname = p4tcpath[DYNACT_PATH_PIPEACTNAME_IDX];

		act = p4tc_find_act(pipe, actname);
		if (!act) {
			fprintf(stderr,"Unable to find action %s\n",
				actname);
			return NULL;
		}
	} else {
		fprintf(stderr, "Invalid action path\n");
		return NULL;
	}

	return act;
}

/* Here path is always pname/cbname/actname.
 * First we try local control block scope, then pipeline (global) scope.
 */
static struct actions_list *
introspect_tbl_action_byname(const char **p4tcpath,
			     const bool introspect_global)
{
	char act_and_cbname[ACTNAMSIZ] = {};
	const char *pname, *cbname, *actname;
	struct p4_tc_pipeline *pipe;
	struct actions_list *act;

	pname = p4tcpath[DYNACT_PATH_PNAME_IDX];
	pipe = p4_tc_import_json(pname);
	if (!pipe) {
		fprintf(stderr, "Unable to find pipeline %s\n",
			pname);
		return NULL;
	}

	cbname = p4tcpath[DYNACT_PATH_CBNAME_IDX];
	actname = p4tcpath[DYNACT_PATH_CBACTNAME_IDX];

	snprintf(act_and_cbname, ACTNAMSIZ, "%s/%s", cbname, actname);

	/* Try first within local control block scope */
	act = p4tc_find_act(pipe, act_and_cbname);
	if (!act) {
		if (introspect_global) {
			/* Try now in pipeline (global) scope */
			act = p4tc_find_act(pipe, actname);
			if (!act) {
				fprintf(stderr,
					"Unable to find action %s nor action %s\n",
					act_and_cbname, actname);
				return NULL;
			}
		}
	}

	return act;
}

static int __parse_dyna(int *argc_p, char ***argv_p, bool in_act,
			struct actions_list *act, struct nlmsghdr *n)
{
	struct tc_act_dyna sel = {0};
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	int parms_count = 1;
	int argc = *argc_p;
	int ok = 0;

	/* After finding the action by using pname and actname, one can
	 * recover the parameters, if the action exists, for introspection.
	 */
	while (argc > 0) {
		if (in_act) {
			if (strcmp(*argv, "param") == 0) {
				if (!tail)
					tail = addattr_nest(n, MAX_MSG,
							    P4TC_ACT_PARMS | NLA_F_NESTED);

				if (dyna_parse_param(&argc, &argv, in_act,
						     &parms_count, act, n) < 0)
					goto err_out;

				if (argc && strcmp(*argv, "param") == 0)
					continue;
			} else {
				break;
			}
		} else {
			if (strcmp(*argv, "param") == 0) {
				if (!tail)
					tail = addattr_nest(n, MAX_MSG,
							    P4TC_ACT_PARMS | NLA_F_NESTED);

				if (dyna_parse_param(&argc, &argv, in_act,
						     &parms_count, act, n) < 0)
					goto err_out;

				if (argc && strcmp(*argv, "param") == 0)
					continue;
			} else if (strcmp(*argv, "state") == 0) {
				NEXT_ARG();
				if (strcmp(*argv, "active") == 0) {
					addattr8(n, MAX_MSG, P4TC_ACT_ACTIVE,
						 1);
				} else if (strcmp(*argv, "inactive") == 0) {
					addattr8(n, MAX_MSG, P4TC_ACT_ACTIVE,
						 0);
				} else {
					fprintf(stderr, "Unknown state\n");
					goto err_out;
				}
			} else {
				break;
			}
		}
		argv++;
		argc--;
	}
	if (tail)
		addattr_nest_end(n, tail);

	if (in_act)
		parse_action_control_dflt(&argc, &argv, &sel.action, false,
					  TC_ACT_PIPE);

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&sel.index, *argv, 10)) {
				fprintf(stderr, "simple: Illegal \"index\" (%s)\n",
					*argv);
				return -1;
			}
			ok += 1;
			argc--;
			argv++;
		}
	}

	if (in_act)
		addattr_l(n, MAX_MSG, P4TC_ACT_OPT, &sel, sizeof(sel));

	*argc_p = argc;
	*argv_p = argv;

	return act ? p4tc_find_action_scope(act) : 0;

err_out:
	usage();
	return -1;
}

static int parse_act_path(char **p4tcpath, char *actname)
{
	char actname_copy[ACTNAMSIZ];
	int num_components;
	int ret;

	ret = try_strncpy(actname_copy, actname, ACTNAMSIZ);
	if (ret < 0) {
		fprintf(stderr, "action name too long\n");
		return -1;
	}
	num_components = parse_path(actname_copy, p4tcpath, "/");
	if (num_components < 0)
		return -1;

	return 0;
}

int parse_dyna(int *argc_p, char ***argv_p, bool in_act, char *actname,
	       struct nlmsghdr *n)
{
	char *p4tcpath[MAX_PATH_COMPONENTS] = {0};
	struct actions_list *act = NULL;

	parse_act_path(p4tcpath, actname);

	if (in_act)
		act = introspect_action_byname((const char **)p4tcpath);

	return __parse_dyna(argc_p, argv_p, in_act, act, n);
}

static bool is_global_act(char *full_actname)
{
	return strchr(full_actname, '/') == NULL;
}

int parse_dyna_tbl_act(int *argc_p, char ***argv_p, char **actname_p,
		       const bool introspect_global, struct nlmsghdr *n)
{
	char *p4tcpath[MAX_PATH_COMPONENTS] = {0};
	struct actions_list *act = NULL;

	parse_act_path(p4tcpath, *actname_p);

	act = introspect_tbl_action_byname((const char **)p4tcpath,
					   introspect_global);
	if (act && introspect_global && is_global_act(act->name)) {
		char *pname = p4tcpath[DYNACT_PATH_PIPEACTNAME_IDX];
		char *actname = p4tcpath[DYNACT_PATH_CBACTNAME_IDX];

		/* Here we now the actname_p string is always
		 * pname/cbname/actname so there is not harm in converting it to
		 * a shorter string, i.e, pname/actname.
		 */
		snprintf(*actname_p, ACTNAMSIZ, "%s/%s", pname, actname);
	}

	return __parse_dyna(argc_p, argv_p, true, act, n);
}

static int
parse_dyna_cb(struct action_util *a, int *argc_p, char ***argv_p, int tca_id,
	      struct nlmsghdr *n)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail;
	int ret;

	NEXT_ARG_FWD();
	tail = addattr_nest(n, MAX_MSG, tca_id | NLA_F_NESTED);
	ret = parse_dyna(&argc, &argv, true, a->id, n);
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

static int print_dyna_parm_value(FILE *f, struct action_util *au,
				 struct p4_type_s *t, struct rtattr *arg,
				 void *mask)
{
	struct rtattr *tb[P4TC_ACT_VALUE_PARAMS_MAX + 1];
	struct p4_type_value val;
	void *value;

	parse_rtattr_nested(tb, P4TC_ACT_VALUE_PARAMS_MAX, arg);

	if (tb[P4TC_ACT_PARAMS_VALUE_OPND]) {
		print_string(PRINT_FP, NULL, "\n\t  value:\n", "");
		open_json_object("value");
		close_json_object();
		print_string(PRINT_FP, NULL, "\t", "");
	} else {
		value = RTA_DATA(tb[P4TC_ACT_PARAMS_VALUE_RAW]);

		val.value = value;
		val.mask = mask;
		if (t->print_p4t)
			t->print_p4t(" value:", "value", &val, f);
	}

	return 0;
}

static int print_dyna_parm(FILE *f, struct action_util *au, struct rtattr *arg)
{
	struct rtattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	struct p4_type_s *t;

	parse_rtattr_nested(tb, P4TC_ACT_PARAMS_MAX, arg);

	if (tb[P4TC_ACT_PARAMS_NAME]) {
		char *name;

		name = RTA_DATA(tb[P4TC_ACT_PARAMS_NAME]);
		print_string(PRINT_ANY, "name", "\t  %s ", name);
	}

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		__u32 contain_id;

		contain_id = *((__u32 *) RTA_DATA(tb[P4TC_ACT_PARAMS_TYPE]));
		t = get_p4type_byid(contain_id);
		if (!t) {
			fprintf(stderr, "Unknown param type %d\n", contain_id);
			return -1;
		}

		print_string(PRINT_ANY, "type", "type %s ", t->name);
	} else {
		fprintf(stderr, "Must specify params type");
		return -1;
	}

	if (tb[P4TC_ACT_PARAMS_VALUE])
		print_dyna_parm_value(f, au, t, tb[P4TC_ACT_PARAMS_VALUE],
				      RTA_DATA(tb[P4TC_ACT_PARAMS_MASK]));

	print_nl();

	if (tb[P4TC_ACT_PARAMS_ID]) {
		__u32 *id;

		id = RTA_DATA(tb[P4TC_ACT_PARAMS_ID]);
		print_uint(PRINT_ANY, "id", " id %u\n", *id);
	}

	return 0;
}

int print_dyna_parms(struct action_util *au, struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, arg);

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		open_json_object(NULL);
		print_dyna_parm(f, au, tb[i]);
		close_json_object();
	}

	return 0;
}

static int print_dyna(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[P4TC_ACT_MAX + 1];
	struct tc_act_dyna *p;

	if (arg == NULL)
		return 0;

	parse_rtattr_nested(tb, P4TC_ACT_MAX, arg);

	if (tb[P4TC_ACT_NAME]) {
		print_string(PRINT_ANY, "kind", "%s ",
			     RTA_DATA(tb[P4TC_ACT_NAME]));
	} else {
		fprintf(stderr, "Action event must have act name");
		return -1;
	}

	if (!tb[P4TC_ACT_PARMS]) {
		fprintf(stderr, "Missing p4tc_cmds parameters\n");
		return -1;
	}

	p = RTA_DATA(tb[P4TC_ACT_OPT]);
	print_uint(PRINT_ANY, "index", " index %u", p->index);
	print_int(PRINT_ANY, "ref", " ref %d", p->refcnt);
	print_int(PRINT_ANY, "bind", " bind %d", p->bindcnt);

	if (show_stats) {
		if (tb[P4TC_ACT_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[P4TC_ACT_TM]);

			print_tm(f, tm);
		}
	}

	if (tb[P4TC_ACT_PARMS]) {
		print_string(PRINT_FP, NULL, "\n\t params:\n", "");
		open_json_array(PRINT_JSON, "params");
		print_dyna_parms(au, tb[P4TC_ACT_PARMS], f);
		close_json_array(PRINT_JSON, NULL);
	}

	strlcpy(au->id, RTA_DATA(tb[P4TC_ACT_NAME]),
		RTA_LENGTH(RTA_PAYLOAD(tb[P4TC_ACT_NAME])));

	return 0;
}

struct action_util dyna_action_util = {
	.id = "dyna",
	.parse_aopt = parse_dyna_cb,
	.print_aopt = print_dyna,
};
