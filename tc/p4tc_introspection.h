/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __P4TC_INTROSPECTION_H__
#define __P4TC_INTROSPECTION_H__
#include <linux/pkt_cls.h>
#include <linux/gen_stats.h>
#include <linux/p4tc.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "p4_types.h"
#include "p4tc_common.h"

#define ENV_VAR "INTROSPECTION"

struct mask_ops { int (*parse)(struct parse_state *state, __u32 *offset,
		     const char *argv);
};

int str_to_type(const char *type_str);
#endif
