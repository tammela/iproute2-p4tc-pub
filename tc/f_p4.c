/*
 * f_p4.c		P4 pipeline Classifier
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/tc_act/tc_bpf.h>

#include "utils.h"
#include "tc_util.h"
#include "bpf_util.h"
#include "p4tc_common.h"

static const enum bpf_prog_type bpf_type = BPF_PROG_TYPE_SCHED_ACT;

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... p4 \n"
		"                 pname PNAME [ action ACTION_SPEC ] [ classid CLASSID ]\n"
		"       ACTION_SPEC := ... look at individual actions\n"
		"\n"
		"NOTE: CLASSID is parsed as hexadecimal input.\n");
}

static void p4tc_ebpf_cb(void *nl, int fd, const char *annotation)
{
	addattr32(nl, MAX_MSG, TCA_ACT_BPF_FD, fd);
	addattrstrz(nl, MAX_MSG, TCA_ACT_BPF_NAME, annotation);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.ebpf_cb = p4tc_ebpf_cb,
};

static int bpf_parse_and_load_common_obj(struct bpf_cfg_in *cfg,
					 const struct bpf_cfg_ops *ops,
					 struct bpf_object **obj, void *nl)
{
	int ret;

	ret = bpf_parse_common(cfg, ops);
	if (ret < 0)
		return ret;

	return bpf_load_common_obj(cfg, ops, obj, nl);
}

struct p4tc_filter_fields {
	__u32 pipeid;
	__u32 handle;
	__u32 chain;
	__u32 classid;
	__u32 blockid;
	__be16 proto;
	__u16 prio;
};

#define RUNT_FIELD_NAMSZ (P4TC_TMPL_NAMSZ * 3)

struct p4tc_filter_runt_field {
	char name[RUNT_FIELD_NAMSZ];
	struct p4_type_s *type;
	void *value;
	size_t offset;
};

static struct p4tc_filter_runt_field *
p4tc_filter_runt_field_find_byname(struct p4tc_filter_runt_field **runt_fields,
				   const char *field_name, int num_runt_fields)
{
	int i;

	for (i = 0; i < num_runt_fields; i++) {
		struct p4tc_filter_runt_field *runt_field = runt_fields[i];

		if (!runt_field)
			continue;

		if (strncmp(field_name, runt_field->name,
			    RUNT_FIELD_NAMSZ) == 0)
			return runt_field;
	}

	return NULL;
}

#define MAX_BSS_SEC_PREFIX_LEN 8
#define BSS_SEC_SUFFIX_LEN (strlen(".bss"))
#define MAX_BSS_SEC_LEN (MAX_BSS_SEC_PREFIX_LEN + BSS_SEC_SUFFIX_LEN + 1)

static int
p4tc_bpf_populate_bss_section(void *p4tc_filter_fields,
			      size_t p4tc_filter_fields_sz,
			      struct bpf_cfg_in *cfg, struct bpf_object *bpf_obj)
{
	char trunc_elf_sec_name[MAX_BSS_SEC_PREFIX_LEN + 1] = {0};
	char elf_sec_name[MAX_BSS_SEC_LEN];
	struct bpf_program *bpf_prog;
	static const int zero = 0;
	struct bpf_map *data_map;
	int err, data_fd;
	__u32 value_size;

	memset(elf_sec_name, 0, MAX_BSS_SEC_LEN);

	bpf_prog = bpf_object__next_program(bpf_obj, NULL);
	if (!bpf_prog) {
		fprintf(stderr, "No BPF programs found in the object\n");
		err = -1;
		goto close_bpf_obj;
	}

	strncpy(trunc_elf_sec_name, cfg->object, MAX_BSS_SEC_PREFIX_LEN);
	snprintf(elf_sec_name, MAX_BSS_SEC_LEN, "%s.bss",
		 trunc_elf_sec_name);
	data_map = bpf_object__find_map_by_name(bpf_obj, elf_sec_name);
	if (!data_map || !bpf_map__is_internal(data_map)) {
		fprintf(stderr, "Failed to get data map %p\n",
			data_map);
		err = -1;
		goto close_bpf_obj;
	}

	value_size = bpf_map__value_size(data_map);
	if (value_size != p4tc_filter_fields_sz) {
		fprintf(stderr,
			"Global in BSS section's size differs from struct p4tc_filter_fields's\n");
		err = -1;
		goto close_bpf_obj;
	}

	data_fd = bpf_map__fd(data_map);
	if (data_fd < 0) {
		fprintf(stderr, "bpf_map__fd failed %d\n", data_fd);
		err = -1;
		goto close_bpf_obj;
	}

	err = bpf_map_update_elem(data_fd, &zero, p4tc_filter_fields, BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "bpf_map_update_elem failed %d\n", err);
		err = -1;
		goto close_bpf_obj;
	}

close_bpf_obj:
	bpf_object__close(bpf_obj);

	return err;
}

static int p4tc_bpf_parse_opt(struct action_util *a, int *ptr_argc,
			      char ***ptr_argv, int tca_id,
			      void *p4tc_filter_fields,
			      size_t p4tc_filter_fields_sz,
			      struct nlmsghdr *n)
{
	struct tc_act_bpf parm = {};
	struct bpf_object *bpf_obj;
	struct bpf_cfg_in cfg = {};
	struct rtattr *tail;
	int argc, ret = 0;
	char **argv;
	int err;

	cfg.verbose = true;

	argv = *ptr_argv;
	argc = *ptr_argc;

	if (strcmp(*argv, "bpf") != 0)
		return -1;

	NEXT_ARG();

	tail = addattr_nest(n, MAX_MSG, tca_id);

	cfg.argc = argc;
	cfg.argv = argv;
	cfg.type = bpf_type;

	if (bpf_parse_and_load_common_obj(&cfg, &bpf_cb_ops, &bpf_obj, n) < 0) {
		fprintf(stderr,
			"Unable to parse bpf command line\n");
		return -1;
	}

	if (!bpf_obj) {
		fprintf(stderr, "Unable to open object\n");
		return -1;
	}

	err = p4tc_bpf_populate_bss_section(p4tc_filter_fields,
					    p4tc_filter_fields_sz, &cfg,
					    bpf_obj);
	if (err < 0)
		return err;

	argc = cfg.argc;
	argv = cfg.argv;

	NEXT_ARG_FWD();

	parse_action_control_dflt(&argc, &argv, &parm.action,
				  false, TC_ACT_PIPE);

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&parm.index, *argv, 10)) {
				fprintf(stderr, "bpf: Illegal \"index\"\n");
				return -1;
			}

			NEXT_ARG_FWD();
		}
	}

	addattr_l(n, MAX_MSG, TCA_ACT_BPF_PARMS, &parm, sizeof(parm));
	addattr_nest_end(n, tail);

	*ptr_argc = argc;
	*ptr_argv = argv;

	return ret;
}

static int p4tc_parse_action(int *argc_p, char ***argv_p, int tca_id,
			     void *p4tc_filter_fields,
			     size_t p4tc_filter_fields_sz,
			     struct nlmsghdr *n)
{
	int argc = *argc_p;
	char **argv = *argv_p;
	struct rtattr *tail, *tail2;
	char k[ACTNAMSIZ];
	int act_ck_len = 0;
	int ok = 0;
	int eap = 0; /* expect action parameters */

	int ret = 0;
	int prio = 0;
	unsigned char act_ck[TC_COOKIE_MAX_SIZE];

	if (argc <= 0)
		return -1;

	tail2 = addattr_nest(n, MAX_MSG, tca_id);

	while (argc > 0) {

		memset(k, 0, sizeof(k));

		if (strcmp(*argv, "keys") == 0 ||
		    strcmp(*argv, "table") == 0 ||
		    strcmp(*argv, "preactions") == 0 ||
		    strcmp(*argv, "table_acts") == 0 ||
		    strcmp(*argv, "postactions") == 0)
			break;

		if (strcmp(*argv, "action") == 0) {
			argc--;
			argv++;
			eap = 1;
			continue;
		} else if (strcmp(*argv, "flowid") == 0) {
			break;
		} else if (strcmp(*argv, "classid") == 0) {
			break;
		} else if (strcmp(*argv, "help") == 0) {
			return -1;
		} else {
			struct action_util *a = NULL;
			int skip_loop = 2;
			__u32 flag = 0;

			if (!action_a2n(*argv, NULL, false))
				strncpy(k, "gact", sizeof(k) - 1);
			else
				strncpy(k, *argv, sizeof(k) - 1);
			eap = 0;
			if (argc > 0) {
				a = get_action_kind(k);
			} else {
				if (ok)
					break;
				else
					goto done;
			}

			if (a == NULL)
				goto bad_val;


			tail = addattr_nest(n, MAX_MSG, ++prio);
			addattr_l(n, MAX_MSG, TCA_ACT_KIND, k, strlen(k) + 1);

			if (strcmp(a->id, "bpf") == 0)
				ret = p4tc_bpf_parse_opt(a, &argc, &argv,
							 TCA_ACT_OPTIONS | NLA_F_NESTED,
							 p4tc_filter_fields,
							 p4tc_filter_fields_sz,
							 n);
			else
				ret = a->parse_aopt(a, &argc, &argv,
						    TCA_ACT_OPTIONS | NLA_F_NESTED,
						    n);

			if (ret < 0) {
				fprintf(stderr, "bad action parsing\n");
				goto bad_val;
			}

			if (*argv && strcmp(*argv, "cookie") == 0) {
				size_t slen;

				NEXT_ARG();
				slen = strlen(*argv);
				if (slen > TC_COOKIE_MAX_SIZE * 2) {
					char cookie_err_m[128];

					snprintf(cookie_err_m, 128,
						 "%zd Max allowed size %d",
						 slen, TC_COOKIE_MAX_SIZE*2);
					invarg(cookie_err_m, *argv);
				}

				if (slen % 2 ||
				    hex2mem(*argv, act_ck, slen / 2) < 0)
					invarg("cookie must be a hex string\n",
					       *argv);

				act_ck_len = slen / 2;
				argc--;
				argv++;
			}

			if (act_ck_len)
				addattr_l(n, MAX_MSG, TCA_ACT_COOKIE,
					  &act_ck, act_ck_len);

			if (*argv && matches(*argv, "hw_stats") == 0) {
				NEXT_ARG();
				ret = parse_hw_stats(*argv, n);
				if (ret < 0)
					invarg("value is invalid\n", *argv);
				NEXT_ARG_FWD();
			}

			if (*argv && strcmp(*argv, "no_percpu") == 0) {
				flag |= TCA_ACT_FLAGS_NO_PERCPU_STATS;
				NEXT_ARG_FWD();
			}

			/* we need to parse twice to fix skip flag out of order */
			while (skip_loop--) {
				if (*argv && strcmp(*argv, "skip_sw") == 0) {
					flag |= TCA_ACT_FLAGS_SKIP_SW;
					NEXT_ARG_FWD();
				} else if (*argv && strcmp(*argv, "skip_hw") == 0) {
					flag |= TCA_ACT_FLAGS_SKIP_HW;
					NEXT_ARG_FWD();
				}
			}

			if (flag) {
				struct nla_bitfield32 flags =
					{ flag, flag };

				addattr_l(n, MAX_MSG, TCA_ACT_FLAGS, &flags,
					  sizeof(struct nla_bitfield32));
			}

			addattr_nest_end(n, tail);
			ok++;
		}
	}

	if (eap > 0) {
		fprintf(stderr, "bad action empty %d\n", eap);
		goto bad_val;
	}

	addattr_nest_end(n, tail2);

done:
	*argc_p = argc;
	*argv_p = argv;
	return 0;
bad_val:
	/* no need to undo things, returning from here should
	 * cause enough pain
	 */
	fprintf(stderr, "p4tc_parse_action: bad value (%d:%s)!\n", argc, *argv);
	return -1;
}

static int p4_parse_prog_opt(int *argc_p, char ***argv_p,
			     struct nlmsghdr *n)
{
	char **argv = *argv_p;
	int argc = *argc_p;

	NEXT_ARG();

	if (strcmp(*argv, "type") == 0) {
		NEXT_ARG();
		if (strcmp(*argv, "xdp") == 0) {
			fprintf(stderr,
				"XDP is currently unsupported\n");
			return -ENOTSUP;
		} else {
			fprintf(stderr,
				"Invalid prog type %s\n",
				*argv);
			return -1;
		}
		NEXT_ARG();
	}

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

#define MAX_FILTER_PARAM_PATH 5

#define PATH_FILTER_PARAM_CBNAME_IDX 0
#define PATH_FILTER_PARAM_TBLNAME_IDX 1
#define PATH_FILTER_PARAM_ACTCBNAME_IDX 2
#define PATH_FILTER_PARAM_ACTNAME_IDX 3
#define PATH_FILTER_PARAM_PARAMNAME_IDX 4
#define PATH_FILTER_PARAM_GLOBAL_ACTNAME_IDX 2
#define PATH_FILTER_PARAM_GLOBAL_PARAMNAME_IDX 3

static struct p4tc_filter_runt_field *
p4tc_filter_runt_field_build_from_param(struct p4tc_json_action_data *param,
					const char *full_runt_field_name,
					const char *val_str)
{
	struct p4tc_filter_runt_field *field;
	struct p4_type_value val;
	struct p4_type_s *t;
	void *new_value;
	void *new_mask;
	__u32 bitsz;
	int ret;

	t = get_p4type_byarg(param->type, &bitsz);
	if (!t) {
		fprintf(stderr, "Invalid type %s\n", param->type);
		return NULL;
	}

	field = calloc(1, sizeof(*field));
	if (!field)
		return NULL;

	ret = try_strncpy(field->name, full_runt_field_name, RUNT_FIELD_NAMSZ);
	if (ret < 0) {
		fprintf(stderr, "Runtime param name too long %s\n",
			full_runt_field_name);
		return NULL;
	}
	field->type = t;
	field->offset =
		BITS_TO_BYTES(param->offset_in_filter_fields);

	new_value = calloc(1, BITS_TO_BYTES(t->bitsz));
	if (!new_value)
		goto free_field;

	new_mask = calloc(1, BITS_TO_BYTES(t->bitsz));
	if (!new_mask)
		goto free_new_value;

	val.value = new_value;
	val.mask = new_mask;
	val.bitsz = bitsz;

	if (t->parse_p4t && t->parse_p4t(&val, val_str, 0) < 0) {
		fprintf(stderr, "Could not parse value for type %s\n",
			t->name);
		goto free_new_mask;
	}
	field->value = new_value;
	free(new_mask);

	return field;

free_new_mask:
	free(new_mask);
free_new_value:
	free(new_value);
free_field:
	free(field);
	return NULL;
}

static int p4_parse_runt_field(int *argc_p, char ***argv_p,
			       struct p4tc_json_pipeline *p,
			       struct p4tc_filter_runt_field **field)
{
	char full_runt_field_name[RUNT_FIELD_NAMSZ] = {0};
	struct p4tc_json_action_data *param;
	struct p4tc_json_actions_list *act;
	char *path[MAX_FILTER_PARAM_PATH];
	char tblname[P4TC_TABLE_NAMSIZ];
	char act_and_cbname[ACTNAMSIZ];
	struct p4tc_json_table *table;
	bool global_act_name = false;
	char *act_cbname = NULL;
	char **argv = *argv_p;
	int argc = *argc_p;
	int num_components;
	char *paramname;
	char *actname;
	int ret = 0;

	ret = try_strncpy(full_runt_field_name, *argv, RUNT_FIELD_NAMSZ);
	if (ret < 0) {
		fprintf(stderr, "Runtime param name too long %s\n",
			*argv);
		return -1;
	}
	num_components = parse_path(*argv, path, "/");
	if (num_components < 0) {
		fprintf(stderr, "Failed to parse filter bind param path");
		return -1;
	}

	if (num_components != MAX_FILTER_PARAM_PATH &&
	    num_components != MAX_FILTER_PARAM_PATH - 1) {
		fprintf(stderr, "Invalid filter bind param path");
		return -1;
	}
	global_act_name = num_components == MAX_FILTER_PARAM_PATH - 1;
	ret = concat_cb_name(tblname, path[PATH_FILTER_PARAM_CBNAME_IDX],
			     path[PATH_FILTER_PARAM_TBLNAME_IDX],
			     P4TC_TABLE_NAMSIZ);
	if (ret < 0) {
		fprintf(stderr, "table name too long");
		return -1;
	}

	table = p4tc_json_find_table(p, tblname);
	if (!table) {
		fprintf(stderr, "Unable to find table %s in JSON file\n",
			tblname);
		return -1;
	}

	if (global_act_name) {
		actname = path[PATH_FILTER_PARAM_GLOBAL_ACTNAME_IDX];
		paramname = path[PATH_FILTER_PARAM_GLOBAL_PARAMNAME_IDX];
	} else {
		act_cbname = path[PATH_FILTER_PARAM_ACTCBNAME_IDX];
		actname = path[PATH_FILTER_PARAM_ACTNAME_IDX];
		paramname = path[PATH_FILTER_PARAM_PARAMNAME_IDX];
	}

	if (act_cbname) {
		ret = concat_cb_name(act_and_cbname, act_cbname, actname,
				     ACTNAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "action name too long");
			return -1;
		}
	} else {
		ret = try_strncpy(act_and_cbname, actname, ACTNAMSIZ);
		if (ret < 0) {
			fprintf(stderr, "actname too long %s\n", actname);
			return -1;
		}
	}

	act = p4tc_json_find_table_act(table, act_and_cbname);
	if (!act) {
		fprintf(stderr, "action %s not found", act_and_cbname);
		return -1;
	}

	param = p4tc_json_find_act_data(act, paramname);
	if (!param) {
		fprintf(stderr, "param %s not found", paramname);
		return -1;
	}

	if (!param->runtime) {
		fprintf(stderr, "param must have runtime flag");
		return -1;
	}

	NEXT_ARG();

	*field = p4tc_filter_runt_field_build_from_param(param,
							 full_runt_field_name,
							 *argv);
	if (!field)
		return -1;

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static void
p4tc_filter_runt_fields_free(struct p4tc_filter_runt_field **runt_fields,
			     int num_runt_fields)
{
	int i;

	for (i = 0; i < num_runt_fields; i++) {
		if (!runt_fields[i])
			break;
		free(runt_fields[i]->value);
		free(runt_fields[i]);
	}
}

struct p4tc_filter_runt_field_iter {
	struct p4tc_filter_runt_field **runt_fields;
	int curr_index;
	int num_runt_params;
};

static int p4_runt_fields_iter(struct p4tc_json_table *table,
			       struct p4tc_json_actions_list *act,
			       struct p4tc_json_action_data *param, void *ptr)
{
	struct p4tc_filter_runt_field_iter *iter = ptr;
	struct p4tc_filter_runt_field **runt_fields = iter->runt_fields;
	char full_runt_field_name[RUNT_FIELD_NAMSZ];
	struct p4tc_filter_runt_field *runt_field;
	int ret;

	ret = snprintf(full_runt_field_name, RUNT_FIELD_NAMSZ, "%s/%s/%s",
		       table->name, act->name, param->name);
	if (ret == RUNT_FIELD_NAMSZ) {
		fprintf(stderr, "Runtime field name too long %s/%s/%s\n",
			table->name, act->name, param->name);
		return -1;
	}

	runt_field = p4tc_filter_runt_field_find_byname(runt_fields,
							full_runt_field_name,
							iter->num_runt_params);
	/* Field was already populated */
	if (runt_field)
		return 0;
	runt_field = p4tc_filter_runt_field_build_from_param(param,
							     full_runt_field_name,
							     param->dflt_val);
	if (!runt_field)
		return -1;

	runt_fields[iter->curr_index] = runt_field;
	iter->curr_index++;

	return 0;
}

static int
p4_fill_missing_runt_fields(struct p4tc_json_pipeline *p,
			    struct p4tc_filter_runt_field **runt_fields)
{
	struct p4tc_filter_runt_field_iter iter = {
		.runt_fields = runt_fields,
		.num_runt_params = p->num_runt_params,
	};
	int ret;

	ret = p4tc_json_for_each_runtime_action_data(p, p4_runt_fields_iter,
						     &iter);
	if (ret < 0) {
		p4tc_filter_runt_fields_free(runt_fields, iter.curr_index);
		return ret;
	}

	return 0;
}

static int p4_parse_runt_fields(int *argc_p, char ***argv_p,
				struct p4tc_json_pipeline *p,
				struct p4tc_filter_runt_field **runt_fields)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int i = 0;

	while (argc > 0) {
		if (strcmp(*argv, "param") == 0) {
			if (i == p->num_runt_params) {
				fprintf(stderr,
					"Exceeded number of runtime parameters (%d)",
					i);
			}

			NEXT_ARG();
			if (p4_parse_runt_field(&argc, &argv, p,
						&runt_fields[i]) < 0)
				return -1;
		} else {
			break;
		}
		NEXT_ARG_FWD();
		i++;
	}

	if (i != p->num_runt_params) {
		fprintf(stderr,
			"Wrong number of runtime parameters %d should be %d",
			i, p->num_runt_params);
	}

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static void *p4tc_filter_fields_init(struct p4tc_json_pipeline *p,
				     struct tc_filter_fields *filter_fields,
				     size_t *p4tc_filter_fields_sz,
				     __u32 pipeid, unsigned int handle,
				     struct p4tc_filter_runt_field **runt_fields)
{
	size_t filter_fields_byte_size = BITS_TO_BYTES(p->filter_fields_size);
	size_t __p4tc_filter_fields_sz = sizeof(struct p4tc_filter_fields);
	struct p4tc_filter_fields *p4tc_filter_fields;
	void *ptr;
	int i;

	*p4tc_filter_fields_sz = __p4tc_filter_fields_sz +
		filter_fields_byte_size;
	ptr = calloc(1, *p4tc_filter_fields_sz);
	if (!ptr)
		return NULL;

	p4tc_filter_fields = (struct p4tc_filter_fields *)ptr;
	p4tc_filter_fields->pipeid = pipeid;
	p4tc_filter_fields->handle = handle;
	p4tc_filter_fields->chain = filter_fields->chain;
	p4tc_filter_fields->classid = filter_fields->classid;
	p4tc_filter_fields->proto = filter_fields->proto;
	p4tc_filter_fields->prio = filter_fields->prio;

	if (!runt_fields)
		return ptr;

	for (i = 0; i < p->num_runt_params; i++) {
		struct p4tc_filter_runt_field *runt_field = runt_fields[i];
		size_t off = __p4tc_filter_fields_sz + runt_field->offset;
		size_t type_sz = BITS_TO_BYTES(runt_field->type->bitsz);

		memcpy(ptr + off, runt_field->value, type_sz);
	}

	return ptr;
}

static int p4_parse_opt(struct filter_util *qu,
			struct tc_filter_fields *filter_fields,
			int argc, char **argv, struct nlmsghdr *n)
{
	struct p4tc_filter_runt_field **runt_fields = NULL;
	char *handle_str = filter_fields->handle;
	struct p4tc_json_pipeline *p = NULL;
	struct tcmsg *t = NLMSG_DATA(n);
	void *p4tc_filter_fields = NULL;
	unsigned int handle = 0;
	struct rtattr *tail;
	char *pname = NULL;
	__u32 pipeid = 0;
	int ret = -1;
	long h = 0;

	if (handle_str) {
		h = strtol(handle_str, NULL, 0);
		if (h == LONG_MIN || h == LONG_MAX) {
			fprintf(stderr, "Illegal handle \"%s\", must be numeric.\n",
				handle_str);
			return -1;
		}
	}
	t->tcm_handle = h;

	if (argc == 0)
		return 0;

	tail = addattr_nest(n, MAX_MSG, TCA_OPTIONS | NLA_F_NESTED);

	while (argc > 0) {
		if (strcmp(*argv, "classid") == 0 ||
		    strcmp(*argv, "flowid") == 0) {
			NEXT_ARG();
			if (get_tc_classid(&handle, *argv)) {
				fprintf(stderr, "Illegal \"classid\"\n");
				goto cleanup;
			}
			addattr32(n, MAX_MSG, TCA_P4_CLASSID, handle);
			filter_fields->classid = handle;
		} else if (strcmp(*argv, "action") == 0) {
			size_t sz;

			NEXT_ARG();
			if (!p) {
				fprintf(stderr,
					"Must specify pipeline name before action");
				goto cleanup;
			}
			ret = p4_fill_missing_runt_fields(p, runt_fields);
			if (ret < 0)
				goto cleanup;
			p4tc_filter_fields = p4tc_filter_fields_init(p,
								     filter_fields,
								     &sz,
								     pipeid,
								     handle,
								     runt_fields);
			if (!p4tc_filter_fields) {
				goto cleanup;
			}
			if (p4tc_parse_action(&argc, &argv,
					      TCA_P4_ACT | NLA_F_NESTED,
					      p4tc_filter_fields, sz, n)) {
				fprintf(stderr, "Illegal \"action\"\n");
				goto cleanup;
			}
			continue;
		} else if (strcmp(*argv, "bind") == 0) {
			if (!p) {
				fprintf(stderr,
					"Must specify pname before bind params");
				goto cleanup;
			}
			NEXT_ARG();
			if (p4_parse_runt_fields(&argc, &argv, p,
						 runt_fields) < 0)
				goto cleanup;
			continue;
		} else if (strcmp(*argv, "pname") == 0) {
			int ret;

			NEXT_ARG();

			pname = *argv;
			addattrstrz(n, MAX_MSG, TCA_P4_PNAME, *argv);
			ret = p4tc_pipeline_get_id(pname, &pipeid);
			if (ret < 0) {
				fprintf(stderr, "Pipeline doesn't exist\n");
				goto cleanup;
			}
			p = p4tc_json_import(pname);
			if (!p) {
				fprintf(stderr, "Unable to find pipeline %s\n",
					pname);
				goto cleanup;
			}

			runt_fields = calloc(p->num_runt_params,
					     sizeof(**runt_fields));
			if (!runt_fields)
				goto cleanup;
		} else if (strcmp(*argv, "prog") == 0) {
			if (p4_parse_prog_opt(&argc, &argv, n) < 0) {
				goto cleanup;
			}
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			goto cleanup;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			goto cleanup;
		}
		argc--; argv++;
	}
	addattr_nest_end(n, tail);

	if (!pname) {
		fprintf(stderr, "pname MUST be provided\n");
		return -1;
	}

	ret = 0;

cleanup:
	if (p)
		p4tc_json_free_pipeline(p);
	if (runt_fields)
		p4tc_filter_runt_fields_free(runt_fields,
					     p->num_runt_params);
	free(runt_fields);

	return ret;
}

static int p4_print_opt(struct filter_util *qu, FILE *f,
			   struct rtattr *opt, __u32 handle)
{
	struct rtattr *tb[TCA_P4_MAX+1];

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_P4_MAX, opt);

	if (handle)
		print_uint(PRINT_ANY, "handle", "handle 0x%x ", handle);

	if (tb[TCA_P4_CLASSID]) {
		SPRINT_BUF(b1);
		print_string(PRINT_ANY, "flowid", "flowid %s ",
			sprint_tc_classid(rta_getattr_u32(tb[TCA_P4_CLASSID]),
					  b1));
	}

	if (tb[TCA_P4_PNAME]) {
		print_string(PRINT_ANY, "pname", "pname %s ",
			     RTA_DATA(tb[TCA_P4_PNAME]));
	} else {
		print_string(PRINT_ANY, "pname", "pname %s ", "???");
	}

	if (tb[TCA_P4_ACT])
		tc_print_action(f, tb[TCA_P4_ACT], 0);

	return 0;
}

struct filter_util p4_filter_util = {
	.id = "p4",
	.parse_fopt = p4_parse_opt,
	.print_fopt = p4_print_opt,
};
