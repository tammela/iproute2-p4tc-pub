/*
 * f_p4.c		P4 pipeline Classifier
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:
 *
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

#define MAX_BSS_SEC_PREFIX_LEN 8
#define BSS_SEC_SUFFIX_LEN (strlen(".bss"))
#define MAX_BSS_SEC_LEN (MAX_BSS_SEC_PREFIX_LEN + BSS_SEC_SUFFIX_LEN + 1)

static int
p4tc_bpf_populate_bss_section(struct p4tc_filter_fields *p4tc_filter_fields,
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
	if (value_size != sizeof(*p4tc_filter_fields)) {
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
			      struct p4tc_filter_fields *p4tc_filter_fields,
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

	err = p4tc_bpf_populate_bss_section(p4tc_filter_fields, &cfg, bpf_obj);
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
			     struct p4tc_filter_fields *p4tc_filter_fields,
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
							 p4tc_filter_fields, n);
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
			     struct p4tc_filter_fields *p4tc_filter_fields,
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

static int p4_parse_opt(struct filter_util *qu,
			struct tc_filter_fields *filter_fields,
			int argc, char **argv, struct nlmsghdr *n)
{
	struct p4tc_filter_fields p4tc_filter_fields = {};
	char *handle = filter_fields->handle;
	struct tcmsg *t = NLMSG_DATA(n);
	struct rtattr *tail;
	char *pname = NULL;
	long h = 0;

	if (handle) {
		h = strtol(handle, NULL, 0);
		if (h == LONG_MIN || h == LONG_MAX) {
			fprintf(stderr, "Illegal handle \"%s\", must be numeric.\n",
			    handle);
			return -1;
		}
	}
	t->tcm_handle = h;
	p4tc_filter_fields.classid = filter_fields->classid;
	p4tc_filter_fields.proto = filter_fields->proto;
	p4tc_filter_fields.prio = filter_fields->prio;
	p4tc_filter_fields.chain = filter_fields->chain;

	if (argc == 0)
		return 0;

	tail = addattr_nest(n, MAX_MSG, TCA_OPTIONS | NLA_F_NESTED);

	while (argc > 0) {
		if (strcmp(*argv, "classid") == 0 ||
		    strcmp(*argv, "flowid") == 0) {
			unsigned int handle;

			NEXT_ARG();
			if (get_tc_classid(&handle, *argv)) {
				fprintf(stderr, "Illegal \"classid\"\n");
				return -1;
			}
			addattr32(n, MAX_MSG, TCA_P4_CLASSID, handle);
			p4tc_filter_fields.handle = handle;
			p4tc_filter_fields.classid = handle;
		} else if (strcmp(*argv, "action") == 0) {
			NEXT_ARG();
			if (p4tc_parse_action(&argc, &argv,
					      TCA_P4_ACT | NLA_F_NESTED,
					      &p4tc_filter_fields, n)) {
				fprintf(stderr, "Illegal \"action\"\n");
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "pname") == 0) {
			__u32 pipeid;
			int ret;

			NEXT_ARG();

			pname = *argv;
			addattrstrz(n, MAX_MSG, TCA_P4_PNAME, *argv);
			ret = p4tc_pipeline_get_id(pname, &pipeid);
			if (ret < 0) {
				fprintf(stderr, "Pipeline doesn't exist\n");
				return -1;
			}
			p4tc_filter_fields.pipeid = pipeid;
		} else if (strcmp(*argv, "prog") == 0) {
			if (p4_parse_prog_opt(&argc, &argv, &p4tc_filter_fields,
					      n) < 0)
				return -1;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}
	addattr_nest_end(n, tail);

	if (!pname) {
		fprintf(stderr, "pname MUST be provided\n");
		return -1;
	}

	return 0;
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
