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

#define ENV_VAR "INTROSPECTION"

int str_to_type(const char *type_str);

struct hdrfield {
	char name[TEMPLATENAMSZ];
	struct p4_type_s *ty;
	__u32 id;
	__u16 startbit;
	__u16 endbit;
};

struct hdrfield *p4tc_find_hdrfield(struct hdrfield fields[],
				    const char *fieldname,
				    __u32 num_fields);
int p4tc_get_header_fields(struct hdrfield fields[], const char *pname,
			   const char *hdrname);
#endif
