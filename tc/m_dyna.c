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

static int dyna_add_param_type(struct p4tc_act_param *param, struct nlmsghdr *n)
{
	struct rtattr *nested_type;

	nested_type = addattr_nest(n, MAX_MSG,
				   P4TC_ACT_PARAMS_TYPE | NLA_F_NESTED);
	addattr16(n, MAX_MSG, P4TC_ACT_PARAMS_TYPE_BITEND, param->bitsz - 1);
	addattr32(n, MAX_MSG, P4TC_ACT_PARAMS_TYPE_CONTAINER_ID,
		  param->type->containid);
	addattr_nest_end(n, nested_type);

	return 0;
}

int dyna_add_param(struct p4tc_act_param *param, void *value, bool in_act,
		   struct nlmsghdr *n, bool convert_value)
{
	int ret = 0;

	addattrstrz(n, MAX_MSG, P4TC_ACT_PARAMS_NAME, param->name);
	if (param->id)
		addattr32(n, MAX_MSG, P4TC_ACT_PARAMS_ID, param->id);
	if (param->type && !(param->flags & (1 << P4TC_ACT_PARAMS_FLAGS_RUNT)))
		dyna_add_param_type(param, n);

	if (in_act &&
	    !(param->flags & (1 << P4TC_ACT_PARAMS_FLAGS_RUNT))) {
		struct p4_type_s *t = param->type;
		struct p4_type_value val;
		struct rtattr *nest_val;
		void *new_value;
		void *new_mask;
		__u32 sz;

		if (convert_value) {
			if (!t) {
				fprintf(stderr, "Must specify param type\n");
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
		} else {
			sz = param->bitsz >> 3;
			new_value = value;
			new_mask = calloc(1, sz);
			if (!new_mask)
				return -1;
		}

		nest_val = addattr_nest(n, MAX_MSG,
					P4TC_ACT_PARAMS_VALUE | NLA_F_NESTED);
		addattr_l(n, MAX_MSG, P4TC_ACT_PARAMS_VALUE_RAW, new_value, sz);
		addattr_nest_end(n, nest_val);

		addattr_l(n, MAX_MSG, P4TC_ACT_PARAMS_MASK, new_mask, sz);

free_mask:
		free(new_mask);
free_value:
		if (convert_value)
			free(new_value);
	} else {
		if (param->flags)
			addattr8(n, MAX_MSG, P4TC_ACT_PARAMS_FLAGS,
				 param->flags);
	}

	return ret;
}

static int dyna_param_copy_name(char *dst_pname, const char *src_pname)
{
	if (strnlen(src_pname, P4TC_ACT_PARAM_NAMSIZ) == P4TC_ACT_PARAM_NAMSIZ)
		return -1;

	strcpy(dst_pname, src_pname);

	return 0;
}

int
p4tc_act_param_build(struct p4tc_json_actions_list *act,
		     struct p4tc_act_param *param, const char *param_name,
		     bool fail_introspection)
{
	struct p4tc_json_action_data *param_info = NULL;

	if (dyna_param_copy_name(param->name, param_name) < 0) {
		fprintf(stderr, "Param name too big");
		return -E2BIG;
	}

	if (act)
		param_info = p4tc_json_find_act_data(act, param->name);

	/* After we get the param name, we can look for it in the P4 JSON file.
	 * If the param is found, we can instrospect its type and ID.
	 */
	if (param_info) {
		struct p4_type_s *t;

		t = get_p4type_byarg(param_info->type, &param->bitsz);
		if (!t) {
			fprintf(stderr, "Invalid type %s\n", param_info->type);
			return -1;
		}
		param->type = t;

		param->id = param_info->id;
	} else if (fail_introspection) {
		return -1;
	}

	return 0;
}

static int dyna_parse_param(int *argc_p, char ***argv_p, bool in_act,
			    int *parms_count, struct p4tc_json_actions_list *act,
			    struct nlmsghdr *n)
{
	struct p4tc_act_param param = {0};
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail2;
	int ret;

	NEXT_ARG();
	tail2 = addattr_nest(n, MAX_MSG, *parms_count | NLA_F_NESTED);
	ret = p4tc_act_param_build(act, &param, *argv, false);
	if (ret < 0) {
		fprintf(stderr, "Param name too big");
		return -E2BIG;
	}

	NEXT_ARG();

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
			param.type = t;
		} else if (strcmp(*argv, "id") == 0) {
			__u32 id;

			NEXT_ARG();
			if (get_u32(&id, *argv, 10)) {
				fprintf(stderr, "Invalid id %s\n",
					*argv);
				return -1;
			}
			param.id = id;
		} else if (in_act && strcmp(*argv, "flags") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "runtime") == 0) {
				param.flags |= (1 << P4TC_ACT_PARAMS_FLAGS_RUNT);
			} else {
				fprintf(stderr, "Unknown flag %s\n", *argv);
				return -1;
			}
		} else {
			break;
		}
		argv++;
		argc--;
	}

	if (dyna_add_param(&param, *argv, in_act, n, true) < 0)
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
struct p4tc_json_actions_list *
introspect_action_byname(struct p4tc_json_pipeline **pipe, const char **p4tcpath)
{
	struct p4tc_json_actions_list *act = NULL;
	const char *pname, *actname;

	pname = p4tcpath[DYNACT_PATH_PNAME_IDX];
	*pipe = p4tc_json_import(pname);
	if (!*pipe) {
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

		act = p4tc_json_find_act(*pipe, act_and_cbname);
		if (!act) {
			fprintf(stderr, "Unable to find action %s\n",
				act_and_cbname);
			goto free_json_pipeline;
		}
	} else if (p4tcpath[DYNACT_PATH_PIPEACTNAME_IDX]) {
		actname = p4tcpath[DYNACT_PATH_PIPEACTNAME_IDX];

		act = p4tc_json_find_act(*pipe, actname);
		if (!act) {
			fprintf(stderr, "Unable to find action %s\n",
				actname);
			goto free_json_pipeline;
		}
	} else {
		fprintf(stderr, "Invalid action path\n");
		goto free_json_pipeline;
	}

	return act;

free_json_pipeline:
	p4tc_json_free_pipeline(*pipe);
	return act;
}

/* Here path is always pname/cbname/actname.
 * First we try local control block scope, then pipeline (global) scope.
 */
static struct p4tc_json_actions_list *
introspect_tbl_action_byname(struct p4tc_json_pipeline **pipe,
			     const char **p4tcpath, const char *tblname,
			     const bool introspect_global)
{
	struct p4tc_json_actions_list *act = NULL;
	const char *pname, *cbname, *actname;
	char act_and_cbname[ACTNAMSIZ] = {};
	struct p4tc_json_table *table;

	pname = p4tcpath[DYNACT_PATH_PNAME_IDX];
	*pipe = p4tc_json_import(pname);
	if (!pipe) {
		fprintf(stderr, "Unable to find pipeline %s in JSON file\n",
			pname);
		return NULL;
	}

	table = p4tc_json_find_table(*pipe, tblname);
	if (!table) {
		fprintf(stderr, "Unable to find table %s in JSON file\n",
			pname);
		goto free_json_pipeline;
	}

	cbname = p4tcpath[DYNACT_PATH_CBNAME_IDX];
	actname = p4tcpath[DYNACT_PATH_CBACTNAME_IDX];

	snprintf(act_and_cbname, ACTNAMSIZ, "%s/%s", cbname, actname);
	/* Try first within local control block scope */
	act = p4tc_json_find_table_act(table, act_and_cbname);
	if (!act) {
		if (introspect_global) {
			/* Try now in pipeline (global) scope */
			act = p4tc_json_find_table_act(table, actname);
			if (!act) {
				fprintf(stderr,
					"Unable to find action %s nor action %s for table %s\n",
					act_and_cbname, actname, tblname);
				goto free_json_pipeline;
			}
		}
	}

	return act;

free_json_pipeline:
	p4tc_json_free_pipeline(*pipe);
	return act;
}

static int __parse_dyna_params_only(int *argc_p, char ***argv_p,
				    struct p4tc_json_actions_list *act,
				    struct nlmsghdr *n)
{
	char **argv = *argv_p;
	int parms_count = 1;
	int argc = *argc_p;

	/* After finding the action by using pname and actname, one can
	 * recover the parameters, if the action exists, for introspection.
	 */
	while (argc > 0) {
		if (strcmp(*argv, "param") == 0) {
			if (dyna_parse_param(&argc, &argv, true,
					     &parms_count, act, n) < 0)
				return -1;

			if (argc && strcmp(*argv, "param") == 0)
				continue;
		} else {
			break;
		}
		argv++;
		argc--;
	}

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int __parse_dyna(int *argc_p, char ***argv_p, bool in_act,
			struct p4tc_json_actions_list *act, struct nlmsghdr *n)
{
	struct tc_act_p4 sel = {0};
	struct rtattr *tail = NULL;
	char **argv = *argv_p;
	int parms_count = 1;
	int argc = *argc_p;

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

				if (argc && strcmp(*argv, "index") == 0)
					break;
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
				fprintf(stderr, "p4act: Illegal \"index\" (%s)\n",
					*argv);
				return -1;
			}
			argc--;
			argv++;
		}
	}

	if (in_act)
		addattr_l(n, MAX_MSG, P4TC_ACT_OPT, &sel, sizeof(sel));

	*argc_p = argc;
	*argv_p = argv;

	return act ? p4tc_json_find_action(act) : 0;

err_out:
	usage();
	return -1;
}

static int parse_act_path(char **p4tcpath, char *actname, char *actname_copy)
{
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
	bool introspect = in_act || p4tc_is_runtime_cmd(n->nlmsg_type);
	char *p4tcpath[MAX_PATH_COMPONENTS] = {0};
	struct p4tc_json_actions_list *act = NULL;
	struct p4tc_json_pipeline *pipe = NULL;
	char actname_copy[ACTNAMSIZ];
	int ret;

	parse_act_path(p4tcpath, actname, actname_copy);

	if (introspect)
		act = introspect_action_byname(&pipe, (const char **)p4tcpath);

	ret = __parse_dyna(argc_p, argv_p, in_act, act, n);

	if (act && introspect)
		p4tc_json_free_pipeline(pipe);

	return ret;
}

static bool is_global_act(char *full_actname)
{
	return strchr(full_actname, '/') == NULL;
}

int parse_dyna_tbl_act(int *argc_p, char ***argv_p, char **actname_p,
		       const char *tblname, const bool introspect_global,
		       struct nlmsghdr *n, bool params_only)
{
	char *p4tcpath[MAX_PATH_COMPONENTS] = {0};
	struct p4tc_json_actions_list *act = NULL;
	struct p4tc_json_pipeline *pipe = NULL;
	char actname_copy[ACTNAMSIZ];
	int ret;

	parse_act_path(p4tcpath, *actname_p, actname_copy);

	act = introspect_tbl_action_byname(&pipe, (const char **)p4tcpath,
					   tblname, introspect_global);
	if (act && introspect_global && is_global_act(act->name)) {
		char *pname = p4tcpath[DYNACT_PATH_PIPEACTNAME_IDX];
		char *actname = p4tcpath[DYNACT_PATH_CBACTNAME_IDX];

		/* Here we now the actname_p string is always
		 * pname/cbname/actname so there is not harm in converting it to
		 * a shorter string, i.e, pname/actname.
		 */
		snprintf(*actname_p, ACTNAMSIZ, "%s/%s", pname, actname);
	}

	if (params_only) {
		ret = __parse_dyna_params_only(argc_p, argv_p, act, n);
		goto free_json_pipeline;
	}

	ret = __parse_dyna(argc_p, argv_p, true, act, n);

free_json_pipeline:
	if (act)
		p4tc_json_free_pipeline(pipe);
	return ret;
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

	if (tb[P4TC_ACT_PARAMS_VALUE_RAW]) {
		value = RTA_DATA(tb[P4TC_ACT_PARAMS_VALUE_RAW]);

		val.value = value;
		val.mask = mask;
		if (t->print_p4t)
			t->print_p4t(" value:", "value", &val, f);
	}

	return 0;
}

static int print_dyna_parm_type(FILE *f, struct rtattr *arg,
				struct p4tc_act_param *param)
{
	struct rtattr *tb[P4TC_ACT_PARAMS_TYPE_MAX + 1];
	struct p4_type_s *type;
	__u32 container_id;
	__u16 bitend;

	parse_rtattr_nested(tb, P4TC_ACT_PARAMS_TYPE_MAX, arg);

	if (tb[P4TC_ACT_PARAMS_TYPE_CONTAINER_ID]) {
		container_id = rta_getattr_u32(tb[P4TC_ACT_PARAMS_TYPE_CONTAINER_ID]);
		type = get_p4type_byid(container_id);
		if (!type) {
			fprintf(stderr, "Unknown param type %d\n",
				container_id);
			return -1;
		}
	} else {
		fprintf(stderr, "Must specify params type container id\n");
		return -1;
	}

	if (tb[P4TC_ACT_PARAMS_TYPE_BITEND]) {
		bitend = rta_getattr_u16(tb[P4TC_ACT_PARAMS_TYPE_BITEND]);
	} else {
		fprintf(stderr, "Must specify params type container id\n");
		return -1;
	}

	if (type->flags & P4TC_T_TYPE_UNSIGNED) {
		char type_name[P4TC_T_MAX_TYPE_NAME];

		sprintf(type_name, "bit%u", bitend + 1);
		print_string(PRINT_ANY, "type", "type %s ", type_name);
	} else if (type->flags & P4TC_T_TYPE_SIGNED) {
		char type_name[P4TC_T_MAX_TYPE_NAME];

		sprintf(type_name, "int%u", bitend + 1);
		print_string(PRINT_ANY, "type", "type %s ", type_name);
	} else {
		print_string(PRINT_ANY, "type", "type %s ", type->name);
	}
	param->type = type;
	param->bitsz = bitend + 1;

	return 0;
}

static int print_dyna_parm(FILE *f, struct action_util *au, struct rtattr *arg)
{
	struct rtattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	struct p4tc_act_param param = {0};

	parse_rtattr_nested(tb, P4TC_ACT_PARAMS_MAX, arg);

	if (tb[P4TC_ACT_PARAMS_NAME]) {
		char *name;

		name = RTA_DATA(tb[P4TC_ACT_PARAMS_NAME]);
		print_string(PRINT_ANY, "name", "\t  %s ", name);
	}

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		int err;

		err = print_dyna_parm_type(f, tb[P4TC_ACT_PARAMS_TYPE], &param);
		if (err < 0)
			return err;
	} else {
		fprintf(stderr, "Must specify params type");
		return -1;
	}

	if (tb[P4TC_ACT_PARAMS_FLAGS]) {
		__u8 *flags = RTA_DATA(tb[P4TC_ACT_PARAMS_FLAGS]);

		if (*flags & (1 << P4TC_ACT_PARAMS_FLAGS_RUNT)) {
			print_string(PRINT_ANY, "flags", "\t %s", "runtime");
		}
	}

	if (tb[P4TC_ACT_PARAMS_VALUE])
		print_dyna_parm_value(f, au, param.type,
				      tb[P4TC_ACT_PARAMS_VALUE],
				      RTA_DATA(tb[P4TC_ACT_PARAMS_MASK]));

	if (tb[P4TC_ACT_PARAMS_ID]) {
		__u32 *id;

		id = RTA_DATA(tb[P4TC_ACT_PARAMS_ID]);
		print_uint(PRINT_ANY, "id", " id %u\n", *id);
	}

	print_nl();

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
	struct tc_act_p4 *p;

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
