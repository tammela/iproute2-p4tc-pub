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

static int str_to_type(const char *type_str)
{
	if (strcmp(type_str, "u8") == 0)
		return P4T_U8;
	else if (strcmp(type_str, "u16") == 0)
		return P4T_U16;
	else if (strcmp(type_str, "u32") == 0)
		return P4T_U32;
	else if (strcmp(type_str, "u64") == 0)
		return P4T_U64;
	else if (strcmp(type_str, "mac") == 0)
		return P4T_MACADDR;
	else if (strcmp(type_str, "ipv4") == 0)
		return P4T_IPV4ADDR;
	else
		return -1;
}

struct param {
	char name[ACTPARAMNAMSIZ];
	__u32 id;
	__u32 type;
};

static int dyna_add_param(struct param *param, const char *value, bool in_act,
			  struct nlmsghdr *n)
{

	addattrstrz(n, MAX_MSG, P4TC_ACT_PARAMS_NAME, param->name);
	if (param->id)
		addattr32(n, MAX_MSG, P4TC_ACT_PARAMS_ID, param->id);
	if (param->type)
		addattr32(n, MAX_MSG, P4TC_ACT_PARAMS_TYPE, param->type);

	if (in_act) {
		void *new_value;
		__u32 sz;

		switch (param->type) {
		case P4T_U8: {
			sz = sizeof(__u8);

			new_value = malloc(sz);
			if (!new_value)
				return -1;
			if (get_u8(new_value, value, 10)) {
				fprintf(stderr, "Invalid u8 %s\n", value);
				free(new_value);
				return -1;
			}
			break;
		}
		case P4T_U16: {
			sz = sizeof(__u16);
			new_value = malloc(sz);
			if (!new_value)
				return -1;
			if (get_u16(new_value, value, 10)) {
				fprintf(stderr, "Invalid u16 %s\n", value);
				free(new_value);
				return -1;
			}
			break;
		}
		case P4T_U32: {
			sz = sizeof(__u32);
			new_value = malloc(sz);
			if (!new_value)
				return -1;
			if (get_u32(new_value, value, 10)) {
				fprintf(stderr, "Invalid u32 %s\n", value);
				free(new_value);
				return -1;
			}
			break;
		}
		case P4T_U64: {
			sz = sizeof(__u64);
			new_value = malloc(sz);
			if (!new_value)
				return -1;
			if (get_u64(new_value, value, 10)) {
				fprintf(stderr, "Invalid u64 %s\n", value);
				free(new_value);
				return -1;
			}
			break;
		}
		case P4T_MACADDR: {
			char mac[ETH_ALEN];

			sz = ETH_ALEN;
			new_value = malloc(sz);
			if (!new_value)
				return -1;
			if (ll_addr_a2n(mac, sz, value) < 0) {
				fprintf(stderr, "mac is invalid %s\n", value);
				free(new_value);
				return -1;
			}
			memcpy(new_value, mac, sz);
			break;
		}
		case P4T_IPV4ADDR: {
			inet_prefix addr;
			__u32 mask;

			if (get_prefix_1(&addr, (char *)value, AF_INET)) {
				fprintf(stderr, "Invalid addr %s\n", value);
				return -1;
			}
			sz = 4;
			new_value = malloc(sz);
			if (!new_value)
				return -1;
			memcpy(new_value, addr.data, sz);

			mask = htonl(~0u << (32 - addr.bitlen));
			addattr32(n, MAX_MSG, P4TC_ACT_PARAMS_MASK, mask);
			break;
		}
		default:
			return -1;
		}

		addattr_l(n, MAX_MSG, P4TC_ACT_PARAMS_VALUE, new_value, sz);
		free(new_value);
	}

	return 0;
}

static int dyna_param_copy_name(char *dst_pname, char *src_pname)
{
	if (strnlen(src_pname, ACTPARAMNAMSIZ) == ACTPARAMNAMSIZ)
		return -1;

	strcpy(dst_pname, src_pname);

	return 0;
}

static int dyna_parse_param(int *argc_p, char ***argv_p, bool in_act,
			    int *parms_count, struct nlmsghdr *n)
{
	struct param param = {0};
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail2;

	NEXT_ARG();
	tail2 = addattr_nest(n, MAX_MSG, *parms_count);
	if (dyna_param_copy_name(param.name, *argv) < 0) {
		fprintf(stderr, "Param name too big");
		return -E2BIG;
	}
	/* After we get the param name, we can look for it in the P4 JSON file.
	 * If the param is found, we can instrospect its type and ID.
	 */
	NEXT_ARG();
	while (argc > 0) {
		if (strcmp(*argv, "type") == 0) {
			int type;

			NEXT_ARG();
			type = str_to_type(*argv);
			if (type < 0) {
				fprintf(stderr, "Invalid type %s\n",
					*argv);
				return -1;
			}
			param.type = type;
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

	addattr_nest_end(n, tail2);
	(*parms_count)++;

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

/* pname and act_name are not used by this function but are important for
 * introspection.
 */
int parse_dyna(int *argc_p, char ***argv_p, bool in_act, char *pname,
	     char *act_name, struct nlmsghdr *n)
{
	struct rtattr *tail = NULL;
	struct tc_act_dyna sel = {0};
	char **argv = *argv_p;
	int parms_count = 1;
	int argc = *argc_p;
	int ok = 0;

	/* After finding the action by using pname and act_name, one can
	 * recover the parameters, if the action exists, for introspection.
	 */
	while (argc > 0) {
		if (in_act) {
			if (strcmp(*argv, "param") == 0) {
				if (!tail)
					tail = addattr_nest(n, MAX_MSG,
							    P4TC_ACT_PARMS);

				if (dyna_parse_param(&argc, &argv, in_act,
						   &parms_count, n) < 0)
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
							    P4TC_ACT_PARMS);

				if (dyna_parse_param(&argc, &argv, in_act,
						   &parms_count, n) < 0)
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
			} else if (strcmp(*argv, "action") == 0) {
				if (parse_action(&argc, &argv, P4TC_ACT_LIST, n)) {
					fprintf(stderr, "Illegal action\"\n");
					return -1;
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

	if (argc > 0) {
		fprintf(stderr, "Unknown argument\n");
		goto err_out;
	}

	if (in_act)
		addattr_l(n, MAX_MSG, P4TC_ACT_OPT, &sel, sizeof(sel));

	*argc_p = argc;
	*argv_p = argv;

	return 0;

err_out:
	usage();
	return -1;
}

static int
parse_dyna_cb(struct action_util *a, int *argc_p, char ***argv_p, int tca_id,
	    struct nlmsghdr *n)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	struct rtattr *tail;
	int ret;

	NEXT_ARG();
	tail = addattr_nest(n, MAX_MSG, tca_id);
	ret = parse_dyna(&argc, &argv, true, NULL, a->id, n);
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;

	return ret;
}

static int print_dyna_parm(FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	__u32 type;

	parse_rtattr_nested(tb, P4TC_ACT_PARAMS_MAX, arg);

	if (tb[P4TC_ACT_PARAMS_NAME]) {
		char *name;

		name = RTA_DATA(tb[P4TC_ACT_PARAMS_NAME]);
		print_string(PRINT_ANY, "name", "\t%s ", name);
	}

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		type = *((__u32 *) RTA_DATA(tb[P4TC_ACT_PARAMS_TYPE]));
		print_string(PRINT_FP, NULL, "type ", NULL);
		switch (type) {
		case P4T_MACADDR:
			print_string(PRINT_ANY, "type", "%s", "mac");
			break;
		case P4T_IPV4ADDR:
			print_string(PRINT_ANY, "type",	"%s", "ipv4");
			break;
		case P4T_U8:
			print_string(PRINT_ANY, "type",	"%s", "u8");
			break;
		case P4T_U16:
			print_string(PRINT_ANY, "type",	"%s", "u16");
			break;
		case P4T_U32:
			print_string(PRINT_ANY, "type",	"%s", "u32");
			break;
		case P4T_U64:
			print_string(PRINT_ANY, "type",	"%s", "u64");
			break;
		}
	} else {
		fprintf(stderr, "Must specify params type");
		return -1;
	}

	if (tb[P4TC_ACT_PARAMS_VALUE]) {
		SPRINT_BUF(b1);
		void *value = RTA_DATA(tb[P4TC_ACT_PARAMS_VALUE]);

		switch (type) {
		case P4T_MACADDR: {
			unsigned char *addr_parm = value;

			ll_addr_n2a(addr_parm, ETH_ALEN, 0, b1, sizeof(b1));
			print_string(PRINT_ANY, "mac", " %s", b1);
			break;
		}
		case P4T_IPV4ADDR: {
			const void *mask_ptr = RTA_DATA(tb[P4TC_ACT_PARAMS_MASK]);
			__u8 addr[4];
			__be32 mask;
			int len;
			SPRINT_BUF(buf1);
			SPRINT_BUF(buf2);

			memcpy(addr, (__u8 *)value, sizeof(addr));

			mask = htonl((*(__be32 *) mask_ptr));
			len = ffs(mask);
			len = len ? 33 - len : 0;
			snprintf(buf2, sizeof(buf2), "%s/%d",
				 format_host_r(AF_INET, 4, addr, buf1, sizeof(buf1)),
				 len);

			print_string(PRINT_ANY, "ipv4", " %s", buf2);
			break;
		}
		case P4T_U8: {
			__u8 *val = value;

			print_uint(PRINT_ANY, "u8", " %u", *val);
			break;
		}
		case P4T_U16: {
			__u16 *val = value;

			print_uint(PRINT_ANY, "u16", " %u", *val);
			break;
		}
		case P4T_U32: {
			__u32 *val = value;

			print_uint(PRINT_ANY, "u32", " %u", *val);
			break;
		}
		case P4T_U64: {
			__u64 *val = value;

			print_uint(PRINT_ANY, "u64", " %u", *val);
			break;
		}
		default:
			break;
		}
	}

	if (tb[P4TC_ACT_PARAMS_ID]) {
		__u32 *id;

		id = RTA_DATA(tb[P4TC_ACT_PARAMS_ID]);
		print_uint(PRINT_ANY, "id", " id %u\n", *id);
	}

	return 0;
}

int print_dyna_parms(struct rtattr *arg, FILE *f)
{
	struct rtattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int i;

	parse_rtattr_nested(tb, P4TC_MSGBATCH_SIZE, arg);

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		open_json_object(NULL);
		print_dyna_parm(f, tb[i]);
		close_json_object();
	}

	return 0;
}

static int print_dyna(struct action_util *au, FILE *f, struct rtattr *arg)
{
	FILE *fp = (FILE *)arg;
	struct rtattr *tb[P4TC_ACT_MAX + 1];
	struct tc_act_dyna *opt;

	parse_rtattr_nested(tb, P4TC_ACT_MAX, arg);

	if (tb[P4TC_ACT_NAME]) {
		const char *name = RTA_DATA(tb[P4TC_ACT_NAME]);

		print_string(PRINT_ANY, "kind", "%s ", name);
		print_nl();
	}

	if (tb[P4TC_ACT_OPT] == NULL) {
		fprintf(stderr, "Missing dyna parameters\n");
		return -1;
	}
	opt = RTA_DATA(tb[P4TC_ACT_OPT]);

	print_string(PRINT_FP, NULL, "%s\t", _SL_);
	print_action_control(f, "action ", opt->action, " ");
	print_nl();

	if (tb[P4TC_ACT_PARMS]) {
		print_string(PRINT_FP, NULL, "\t%s\n", "params: ");
		open_json_array(PRINT_JSON, "params");
		print_dyna_parms(tb[P4TC_ACT_PARMS], f);
		close_json_array(PRINT_JSON, NULL);
	}

	if (tb[P4TC_ACT_LIST]) {
		print_nl();
		print_string(PRINT_FP, NULL, "    Action list:\n", NULL);
		tc_print_action(fp, tb[P4TC_ACT_LIST], 0);
	}

	print_nl();
	print_uint(PRINT_ANY, "index", "\t index %u", opt->index);
	print_int(PRINT_ANY, "ref", " ref %d", opt->refcnt);
	print_int(PRINT_ANY, "bind", " bind %d", opt->bindcnt);

	if (show_stats) {
		if (tb[P4TC_ACT_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[P4TC_ACT_TM]);

			print_tm(f, tm);
		}
	}

	print_nl();

	return 0;
}

struct action_util dyna_action_util = {
	.id = "dyna",
	.parse_aopt = parse_dyna_cb,
	.print_aopt = print_dyna,
};
