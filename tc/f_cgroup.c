/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * f_cgroup.c		Control Group Classifier
 *
 * Authors:	Thomas Graf <tgraf@infradead.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "tc_util.h"
#include "m_ematch.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... cgroup [ match EMATCH_TREE ]\n");
	fprintf(stderr, "                  [ action ACTION_SPEC ]\n");
}

static int cgroup_parse_opt(const struct filter_util *qu,
			    struct tc_filter_fields *filter_fields,
			    int argc, char **argv, struct nlmsghdr *n)
{
	char *handle = filter_fields->handle;
	struct tcmsg *t = NLMSG_DATA(n);
	struct rtattr *tail;
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

	tail = (struct rtattr *)(((void *)n)+NLMSG_ALIGN(n->nlmsg_len));
	addattr_l(n, MAX_MSG, TCA_OPTIONS, NULL, 0);

	while (argc > 0) {
		if (matches(*argv, "match") == 0) {
			NEXT_ARG();
			if (parse_ematch(&argc, &argv, TCA_CGROUP_EMATCHES, n)) {
				fprintf(stderr, "Illegal \"ematch\"\n");
				return -1;
			}
			continue;
		} else if (matches(*argv, "action") == 0) {
			NEXT_ARG();
			if (parse_action(&argc, &argv, TCA_CGROUP_ACT, n)) {
				fprintf(stderr, "Illegal \"action\"\n");
				return -1;
			}
			continue;

		} else if (matches(*argv, "police") == 0) {
			NEXT_ARG();
			if (parse_police(&argc, &argv, TCA_CGROUP_POLICE, n)) {
				fprintf(stderr, "Illegal \"police\"\n");
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
	}

	tail->rta_len = (((void *)n)+n->nlmsg_len) - (void *)tail;
	return 0;
}

static int cgroup_print_opt(const struct filter_util *qu, FILE *f,
			   struct rtattr *opt, __u32 handle)
{
	struct rtattr *tb[TCA_CGROUP_MAX+1];

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_CGROUP_MAX, opt);

	if (handle)
		print_0xhex(PRINT_ANY, "handle", "handle %#llx ", handle);

	if (tb[TCA_CGROUP_EMATCHES])
		print_ematch(f, tb[TCA_CGROUP_EMATCHES]);

	if (tb[TCA_CGROUP_POLICE]) {
		print_nl();
		tc_print_police(tb[TCA_CGROUP_POLICE]);
	}

	if (tb[TCA_CGROUP_ACT])
		tc_print_action(f, tb[TCA_CGROUP_ACT], 0);

	return 0;
}

struct filter_util cgroup_filter_util = {
	.id = "cgroup",
	.parse_fopt = cgroup_parse_opt,
	.print_fopt = cgroup_print_opt,
};
