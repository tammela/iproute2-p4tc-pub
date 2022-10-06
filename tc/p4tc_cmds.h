/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _P4TC_CMDS_H_
#define _P4TC_CMDS_H_

#include "tc_util.h"

int p4tc_parse_cmds(struct action_util *a, int *argc_p, char ***argv_p);
int p4tc_add_cmds(struct nlmsghdr *n, int ins_cnt, int tca_id);
int p4tc_print_cmds(FILE *f, struct action_util *au, struct rtattr *arg);
int p4tc_cmds_print_operand(const char *ABC, struct action_util *au,
			    struct rtattr *op_attr, FILE *f);

#endif
