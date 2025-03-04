/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * tc_monitor.c		"tc monitor".
 *
 * Authors:	Jamal Hadi Salim
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include "rt_names.h"
#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"
#include "p4tc_common.h"


static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr, "Usage: tc [-timestamp [-tshort] monitor\n");
	exit(-1);
}


static int accept_tcmsg(struct rtnl_ctrl_data *ctrl,
			struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;

	if (timestamp)
		print_timestamp(fp);

	if (n->nlmsg_type == RTM_NEWTFILTER ||
	    n->nlmsg_type == RTM_DELTFILTER ||
	    n->nlmsg_type == RTM_NEWCHAIN ||
	    n->nlmsg_type == RTM_DELCHAIN) {
		print_filter(n, arg);
		return 0;
	}
	if (n->nlmsg_type == RTM_NEWTCLASS || n->nlmsg_type == RTM_DELTCLASS) {
		print_class(n, arg);
		return 0;
	}
	if (n->nlmsg_type == RTM_NEWQDISC || n->nlmsg_type == RTM_DELQDISC) {
		print_qdisc(n, arg);
		return 0;
	}
	if (n->nlmsg_type == RTM_GETACTION || n->nlmsg_type == RTM_NEWACTION ||
	    n->nlmsg_type == RTM_DELACTION) {
		print_action(n, arg);
		return 0;
	}

	if (n->nlmsg_type == RTM_CREATEP4TEMPLATE ||
	    n->nlmsg_type == RTM_UPDATEP4TEMPLATE ||
	    n->nlmsg_type == RTM_GETP4TEMPLATE ||
	    n->nlmsg_type == RTM_DELP4TEMPLATE) {
		print_p4tmpl(n, arg);
		return 0;
	}

	if (n->nlmsg_type == RTM_P4TC_CREATE ||
	    n->nlmsg_type == RTM_P4TC_UPDATE ||
	    n->nlmsg_type == RTM_P4TC_DEL ||
	    n->nlmsg_type == RTM_P4TC_GET) {
		print_p4ctrl(n, arg);
		return 0;
	}

	if (n->nlmsg_type != NLMSG_ERROR && n->nlmsg_type != NLMSG_NOOP &&
	    n->nlmsg_type != NLMSG_DONE) {
		fprintf(stderr, "Unknown message: length %08d type %08x flags %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
	}
	return 0;
}

int do_tcmonitor(int argc, char **argv)
{
	struct rtnl_handle rth;
	char *file = NULL;
	unsigned int groups = 0;
#ifdef P4TC
	bool has_filter = false;
#endif

	while (argc > 0) {
		if (matches(*argv, "file") == 0) {
			NEXT_ARG();
			file = *argv;
#ifdef P4TC
		} else if (strcmp(*argv, "p4") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "events") == 0) {
				groups = RTNLGRP_P4TC;
				if (NEXT_ARG_OK()) {
					has_filter = true;
					break;
				}
			} else if (strcmp(*argv, "digest") == 0) {
				groups = RTNLGRP_P4TC_DIGEST;
			} else {
				fprintf(stderr,
					"Argument \"p4\" should be proceeded by events or digest and not \"%s\"\n",
					*argv);
				exit(-1);
			}
#endif
		} else {
			if (matches(*argv, "help") == 0) {
				usage();
			} else {
				fprintf(stderr, "Argument \"%s\" is unknown, try \"tc monitor help\".\n", *argv);
				exit(-1);
			}
		}
		argc--;	argv++;
	}

	if (file) {
		FILE *fp = fopen(file, "r");
		int ret;

		if (!fp) {
			perror("Cannot fopen");
			exit(-1);
		}

		ret = rtnl_from_file(fp, accept_tcmsg, stdout);
		fclose(fp);
		return ret;
	}
#ifdef P4TC
	if (groups) {
		if (rtnl_open(&rth, 0) < 0)
			exit(1);
		if (rtnl_add_nl_group(&rth, groups) < 0) {
			fprintf(stderr,
				"Failed to subscribe to P4TC rtnl group\n");
			rtnl_close(&rth);
			exit(1);
		}
	} else {
		groups = nl_mgrp(RTNLGRP_TC);
		if (rtnl_open(&rth, groups) < 0)
			exit(1);
	}
#else
	groups = nl_mgrp(RTNLGRP_TC);
	if (rtnl_open(&rth, groups) < 0)
		exit(1);
#endif

	ll_init_map(&rth);

#ifdef P4TC
	if (has_filter) {
		int ret;

		if (groups == RTNLGRP_P4TC_DIGEST) {
			fprintf(stderr,
				"Filter with digest is not yet supported\n");
			exit(1);
		}
		if (groups != RTNLGRP_P4TC) {
			fprintf(stderr,
				"Filter may only be used for P4TC group\n");
			exit(1);
		}

		ret = tc_filter(&rth, &argc, &argv);
		if (ret < 0)
			return ret;
	}
#endif

	if (rtnl_listen(&rth, accept_tcmsg, (void *)stdout) < 0) {
		rtnl_close(&rth);
		exit(2);
	}

	rtnl_close(&rth);
	exit(0);
}
