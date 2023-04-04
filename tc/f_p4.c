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

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... p4 \n"
		"                 pname PNAME [ action ACTION_SPEC ] [ classid CLASSID ]\n"
		"       ACTION_SPEC := ... look at individual actions\n"
		"\n"
		"NOTE: CLASSID is parsed as hexadecimal input.\n");
}

static int p4_parse_opt(struct filter_util *qu, char *handle,
			   int argc, char **argv, struct nlmsghdr *n)
{
	struct tcmsg *t = NLMSG_DATA(n);
	char *pname = NULL;
	long h = 0;
	struct rtattr *tail;

	if (handle) {
		h = strtol(handle, NULL, 0);
		if (h == LONG_MIN || h == LONG_MAX) {
			fprintf(stderr, "Illegal handle \"%s\", must be numeric.\n",
			    handle);
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
			unsigned int handle;

			NEXT_ARG();
			if (get_tc_classid(&handle, *argv)) {
				fprintf(stderr, "Illegal \"classid\"\n");
				return -1;
			}
			addattr_l(n, MAX_MSG, TCA_P4_CLASSID, &handle, 4);
		} else if (strcmp(*argv, "action") == 0) {
			NEXT_ARG();
			if (parse_action(&argc, &argv, TCA_P4_ACT, n)) {
				fprintf(stderr, "Illegal \"action\"\n");
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "pname") == 0) {

			NEXT_ARG();

			pname = *argv;
			addattr_l(n, MAX_MSG, TCA_P4_PNAME, *argv,
				  PIPELINENAMSIZ);

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
